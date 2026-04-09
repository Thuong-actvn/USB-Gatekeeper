#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/usb.h>
#include <net/sock.h>
#include <linux/sched.h>
#include "../netlink_proto.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Thuo_ng");
MODULE_DESCRIPTION("USB Gatekeeper");
MODULE_VERSION("1.0");

static struct sock *nl_sk = NULL;
static int user_pid = 0; /* Lưu PID của ứng dụng User Space */

/* Hàm Helper bằng bash để kiểm soát sysfs do các API nội bộ không phải lúc nào cũng được export */
static void k_set_usb_authorized_default(int val)
{
    char cmd[256];
    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    
    snprintf(cmd, sizeof(cmd), 
        "echo %d > /sys/module/usbcore/parameters/authorized_default 2>/dev/null; "
        "for f in /sys/bus/usb/devices/usb*/authorized_default; do echo %d > \"$f\" 2>/dev/null; done", 
        val, val);
    
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

static void k_authorize_usb(int busnum, int devnum) 
{
    char cmd[512];
    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    
    /* Chạy kịch bản shell duyệt qua USB dev, dùng 'read' tích hợp của shell thay vì 'cat' (tạo tiến trình con làm chậm hệ thống) */
    snprintf(cmd, sizeof(cmd),
        "for d in /sys/bus/usb/devices/*; do "
        "if [ -f \"$d/busnum\" ] && [ -f \"$d/devnum\" ]; then "
        "read b < \"$d/busnum\"; read v < \"$d/devnum\"; "
        "if [ \"$b\" = \"%d\" ] && [ \"$v\" = \"%d\" ]; then "
        "echo 1 > \"$d/authorized\" 2>/dev/null; break; fi; fi; done",
        busnum, devnum);
        
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/* Xử lý khi nhận bản tin từ User Space */
static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct gatekeeper_msg *msg;
    
    nlh = (struct nlmsghdr *)skb->data;
    
    /* Kiểm tra chiều dài hợp lệ */
    if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct gatekeeper_msg)))
        return;
        
    msg = (struct gatekeeper_msg *)nlmsg_data(nlh);
    if (msg->action == ACTION_HELLO) {
        user_pid = nlh->nlmsg_pid;
        pr_info("USB-Gatekeeper: Ứng dụng User Space (PID %d) đã kết nối\n", user_pid);
    } 
    else if (msg->action == ACTION_ALLOW) {
        pr_info("USB-Gatekeeper: Người dùng CHO PHÉP thiết bị (Bus: %d, Dev: %d)\n", msg->busnum, msg->devnum);
        k_authorize_usb(msg->busnum, msg->devnum);
    } 
    else if (msg->action == ACTION_DENY) {
        pr_info("USB-Gatekeeper: Người dùng CHẶN thiết bị (Bus: %d, Dev: %d)\n", msg->busnum, msg->devnum);
        // Với lệnh DENY ta không làm gì vì default là block
    }
}

/* Hàm hook vào USB subsystem, tự động gọi khi cắm thiết bị */
static int usb_notify(struct notifier_block *self, unsigned long action, void *dev)
{
    struct usb_device *udev = dev;
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    struct gatekeeper_msg *msg;
    int res;
    
    if (action != USB_DEVICE_ADD && action != USB_DEVICE_REMOVE)
        return NOTIFY_OK;
        
    if (action == USB_DEVICE_ADD) {
        pr_info("USB-Gatekeeper: Thiết bị USB mới cắm (VID: %04x, PID: %04x, Hãng: %s, Tên: %s, Serial: %s)\n", 
               le16_to_cpu(udev->descriptor.idVendor), 
               le16_to_cpu(udev->descriptor.idProduct),
               udev->manufacturer ? udev->manufacturer : "N/A",
               udev->product ? udev->product : "N/A",
               udev->serial ? udev->serial : "N/A");
    } else {
        pr_info("USB-Gatekeeper: Thiết bị USB bị rút (VID: %04x, PID: %04x, Hãng: %s, Tên: %s)\n", 
               le16_to_cpu(udev->descriptor.idVendor), 
               le16_to_cpu(udev->descriptor.idProduct),
               udev->manufacturer ? udev->manufacturer : "N/A",
               udev->product ? udev->product : "N/A");
    }
           
    if (user_pid == 0) {
        if (action == USB_DEVICE_ADD) {
            pr_info("USB-Gatekeeper: Không có ứng dụng lằng nghe, thiết bị bị chặn.\n");
        }
        return NOTIFY_OK;
    }
    
    /* Chuẩn bị gửi lên User, dùng GFP_ATOMIC vì hàm được gọi từ notifier chain context */
    skb_out = nlmsg_new(sizeof(struct gatekeeper_msg), GFP_ATOMIC);
    if (!skb_out) {
        pr_err("USB-Gatekeeper: Lỗi hết bộ nhớ (nlmsg_new GFP_ATOMIC)\n");
        return NOTIFY_OK;
    }
    
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sizeof(struct gatekeeper_msg), 0);
    msg = nlmsg_data(nlh);
    memset(msg, 0, sizeof(struct gatekeeper_msg));
    
    msg->action = (action == USB_DEVICE_ADD) ? ACTION_NOTIFY : ACTION_REMOVE;
    msg->busnum = udev->bus->busnum;
    msg->devnum = udev->devnum;
    msg->idVendor = le16_to_cpu(udev->descriptor.idVendor);
    msg->idProduct = le16_to_cpu(udev->descriptor.idProduct);

    if (udev->manufacturer) {
        strncpy(msg->manufacturer, udev->manufacturer, sizeof(msg->manufacturer) - 1);
    }
    if (udev->product) {
        strncpy(msg->product, udev->product, sizeof(msg->product) - 1);
    }
    if (udev->serial) {
        strncpy(msg->serial, udev->serial, sizeof(msg->serial) - 1);
    }
    
    /* Bắn unicast về app */
    res = nlmsg_unicast(nl_sk, skb_out, user_pid);
    if (res < 0) {
        pr_err("USB-Gatekeeper: Lỗi gửi tin tới PID %d (App có thể đã bị tắt). Đã reset trạng thái.\n", user_pid);
        user_pid = 0;
    }
    
    return NOTIFY_OK;
}

static struct notifier_block usb_nb = {
    .notifier_call = usb_notify,
};

static int __init gatekeeper_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };
    
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USB_GATEKEEPER, &cfg);
    if (!nl_sk) {
        pr_err("USB-Gatekeeper: Khởi tạo Netlink Socket thất bại.\n");
        return -ENOMEM;
    }
    
    usb_register_notify(&usb_nb);
    
    /* Chặn USB mặc định */
    k_set_usb_authorized_default(0);
    pr_info("USB-Gatekeeper: Module tải thành công. MỌI USB MỚI SẼ KẾT NỐI BỊ CHẶN.\n");
    
    return 0;
}

static void __exit gatekeeper_exit(void)
{
    netlink_kernel_release(nl_sk);
    usb_unregister_notify(&usb_nb);
    
    /* Khi unload module, khôi phục lại cơ chế USB bình thường */
    k_set_usb_authorized_default(1);
    pr_info("USB-Gatekeeper: Module gỡ bỏ! Reset authorized_default = 1.\n");
}

module_init(gatekeeper_init);
module_exit(gatekeeper_exit);
