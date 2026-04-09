#ifndef NETLINK_PROTO_H
#define NETLINK_PROTO_H

#define NETLINK_USB_GATEKEEPER 31 /* Protocol Number tùy chỉnh */

#define ACTION_HELLO  0
#define ACTION_NOTIFY 1
#define ACTION_ALLOW  2
#define ACTION_DENY   3
#define ACTION_REMOVE 4

struct gatekeeper_msg {
    int action;
    int busnum;
    int devnum;
    unsigned int idVendor;
    unsigned int idProduct;
    char manufacturer[64];
    char product[64];
    char serial[64];
};

#endif /* NETLINK_PROTO_H */
