#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <termios.h>
#include "../netlink_proto.h"

#define MAX_PAYLOAD 1024

int main() {
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    int sock_fd;
    struct msghdr msg;
    struct gatekeeper_msg *gk_data;

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

    printf("[+] U-Gatekeeper sẵn sàng.\n");
    

    /* Loop lắng nghe kernel */
    while (1) {
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        recvmsg(sock_fd, &msg, 0);
        
        gk_data = (struct gatekeeper_msg *)NLMSG_DATA(nlh);

        if (gk_data->action == ACTION_NOTIFY) {
            printf("\n------------------------------------------------\n");
            printf("[!] THIẾT BỊ MỚI:\n");
            printf("    Bus ID: %d | Device Num: %d\n", gk_data->busnum, gk_data->devnum);
            printf("    VID: %04x | PID: %04x\n", gk_data->idVendor, gk_data->idProduct);
            printf("    Manufacturer: %s\n", strlen(gk_data->manufacturer) > 0 ? gk_data->manufacturer : "N/A");
            printf("    Product:  %s\n", strlen(gk_data->product) > 0 ? gk_data->product : "N/A");
            printf("    Serial:     %s\n", strlen(gk_data->serial) > 0 ? gk_data->serial : "N/A");
            
            printf("\n    [?] CHO PHÉP thiết bị này? (Y/n): ");
            fflush(stdout);
            
            char input[10];
            tcflush(STDIN_FILENO, TCIFLUSH); /* Xóa buffer terminal */
            fflush(stdin);                   /* Xóa buffer stdio */
            
            if (fgets(input, sizeof(input), stdin) == NULL) {
                break;
            }
            
            /* Đọc hết ký tự thừa nếu nhập quá dài */
            if (strchr(input, '\n') == NULL) {
                int ch;
                while ((ch = fgetc(stdin)) != '\n' && ch != EOF);
            }
            
            int saved_busnum = gk_data->busnum;
            int saved_devnum = gk_data->devnum;

            /* Gửi respond ngược cho kernel */
            memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
            nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
            nlh->nlmsg_pid = 0;
            nlh->nlmsg_flags = 0;
            
            struct gatekeeper_msg *reply = (struct gatekeeper_msg *)NLMSG_DATA(nlh);
            reply->busnum = saved_busnum;
            reply->devnum = saved_devnum;
            
            if (input[0] == 'y' || input[0] == 'Y' || input[0] == '\n' || input[0] == '\r') { // Default to Allow on Enter
                reply->action = ACTION_ALLOW;
                printf("[+] Đã gửi tín hiệu CHO PHÉP.\n");
            } else {
                reply->action = ACTION_DENY;
                printf("[-] Đã gửi tín hiệu CHẶN.\n");
            }
            
            sendmsg(sock_fd, &msg, 0);
        } else if (gk_data->action == ACTION_REMOVE) {
            printf("\n------------------------------------------------\n");
            printf("[-] THIẾT BỊ VỪA BỊ RÚT RA:\n");
            printf("    Bus ID: %d | Device Num: %d\n", gk_data->busnum, gk_data->devnum);
            printf("    VID: %04x | PID: %04x\n", gk_data->idVendor, gk_data->idProduct);
            printf("    Manufacturer: %s\n", strlen(gk_data->manufacturer) > 0 ? gk_data->manufacturer : "N/A");
            printf("    Product:  %s\n", strlen(gk_data->product) > 0 ? gk_data->product : "N/A");
            printf("    Serial:     %s\n", strlen(gk_data->serial) > 0 ? gk_data->serial : "N/A");
            printf("------------------------------------------------\n");
        }
    }

    close(sock_fd);
    free(nlh);
    return 0;
}
