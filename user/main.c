#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include "../netlink_proto.h"
#include <sys/wait.h>

#define MAX_PAYLOAD 1024

/*
 * Hàm hiển thị popup khi có thiết bị mới.
 * Trả về: 1 (Cho phép), 0 (Chặn)
 */
int show_os_popup(struct gatekeeper_msg *gk_data) {
    char cmd[2048];
    
    // Câu lệnh Bash để lấy màn hình của User đang đăng nhập và gọi Zenity
    snprintf(cmd, sizeof(cmd),
        "REAL_USER=$(who | grep -v root | awk '{print $1}' | head -n1); " //lấy user thường dùng đang đăng nhập (bỏ qua root)   
        "if [ -z \"$REAL_USER\" ]; then REAL_USER=${SUDO_USER:-$USER}; fi; " // Nếu không tìm thấy user nào đang đăng nhập, fallback sang SUDO_USER hoặc USER
        "sudo -u $REAL_USER DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u $REAL_USER)/bus "
        "zenity --question "
        "--title='USB Gatekeeper' "
        "--text='<b>Thiết bị USB mới!</b>\n\n"
        "<b>Thông tin thiết bị:</b>\n"
        "   Hãng sản xuất: %s\n"
        "   Tên sản phẩm: %s\n"
        "   Serial: %s\n"
        "   VID:PID: <b>%04x:%04x</b>' "
        "--ok-label='Cho phép' "
        "--cancel-label='Chặn' "
        "--window-icon=dialog-warning "
        "--width=300 2>/dev/null", 
        strlen(gk_data->manufacturer) > 0 ? gk_data->manufacturer : "N/A",
        strlen(gk_data->product) > 0 ? gk_data->product : "N/A",
        strlen(gk_data->serial) > 0 ? gk_data->serial : "N/A",
        gk_data->idVendor, gk_data->idProduct);

    // Mở popup
    int status = system(cmd);
    
    // Nếu cửa sổ thoát bình thường và user click "Cho phép"
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 1; // ALLOW
    }
    return 0; // DENY (Bao gồm click Chặn, hoặc nhấn X tắt cửa sổ)
}

/*
 * Thông báo khi rút USB
 */
void show_remove_notification(struct gatekeeper_msg *gk_data) {
    char cmd[1024];
    
    snprintf(cmd, sizeof(cmd),
        "REAL_USER=$(who | grep -v root | awk '{print $1}' | head -n1); "
        "if [ -z \"$REAL_USER\" ]; then REAL_USER=${SUDO_USER:-$USER}; fi; "
        "sudo -u $REAL_USER DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u $REAL_USER)/bus "
        "notify-send "
        "-t 3000 "
        "-i drive-removable-media "
        "'USB Gatekeeper' "
        "'Đã ngắt kết nối thiết bị USB:\n%s' 2>/dev/null &", 
         strlen(gk_data->product) > 0 ? gk_data->product : "N/A");

    system(cmd);
}

int main() {
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    int sock_fd;
    struct msghdr msg;
    struct gatekeeper_msg *gk_data;

    // Bắt buộc quyền root
    if (geteuid() != 0) {
        fprintf(stderr, "[-] Yêu cầu quyền root\n");
        return -1;
    }

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USB_GATEKEEPER);
    if (sock_fd < 0) {
        perror("[-] Lỗi tạo socket Netlink");
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* PID của User space app */

    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        perror("[-] Lỗi bind socket Netlink");
        close(sock_fd);
        return -1;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; /* Gui cho Kernel */
    dest_addr.nl_groups = 0; /* Unicast */

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_flags = 0;

    gk_data = (struct gatekeeper_msg *)NLMSG_DATA(nlh);
    gk_data->action = ACTION_HELLO; 
    
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("[+] Cổng Netlink gửi tín hiệu kết nối Kernel...\n");
    sendmsg(sock_fd, &msg, 0);

    printf("[+] U-Gatekeeper sẵn sàng. Đang giám sát thiết bị...\n");
    
    /* Loop lắng nghe kernel */
    while (1) {
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        recvmsg(sock_fd, &msg, 0);
        
        gk_data = (struct gatekeeper_msg *)NLMSG_DATA(nlh);

        if (gk_data->action == ACTION_NOTIFY) {
            // Lưu lại vị trí thiết bị trước khi tái sử dụng buffer
            int saved_busnum = gk_data->busnum;
            int saved_devnum = gk_data->devnum;

            // Gọi hàm Popup GUI
            int is_allowed = show_os_popup(gk_data);

            /* Chuẩn bị gói tin gửi respond ngược cho kernel */
            memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
            nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
            nlh->nlmsg_pid = 0;
            nlh->nlmsg_flags = 0;
            
            struct gatekeeper_msg *reply = (struct gatekeeper_msg *)NLMSG_DATA(nlh);
            reply->busnum = saved_busnum;
            reply->devnum = saved_devnum;
            
            if (is_allowed) {
                reply->action = ACTION_ALLOW;
                printf("[+] => User đã CHO PHÉP qua giao diện.\n");
            } else {
                reply->action = ACTION_DENY;
                printf("[-] => User đã CHẶN qua giao diện.\n");
            }
            
            // Gửi quyết định xuống Kernel
            sendmsg(sock_fd, &msg, 0);
            
        } else if (gk_data->action == ACTION_REMOVE) {
            show_remove_notification(gk_data);
        }
    }

    close(sock_fd);
    free(nlh);
    return 0;
}
