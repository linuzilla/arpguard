#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include "packet.h"


static struct linux_packet_data_t {
    int sockfd;
    struct msghdr msg;
    struct iovec iv;
    union {
        struct cmsghdr cm;
        u_int8_t pktinfo_sizer[sizeof (struct cmsghdr) + 1024];
    } control_un;
} singleton_data, *data;

static struct linux_packet_t singleton, *self;


static int iface_get_id (int fd, const char *device) {
    struct ifreq ifr;

    memset (&ifr, 0, sizeof (ifr) );
    strncpy (ifr.ifr_name, device, sizeof (ifr.ifr_name) - 1);

    if (ioctl (fd, SIOCGIFINDEX, &ifr) == -1) {
        perror ("ioctl");
        return -1;
    }

    return ifr.ifr_ifindex;
}

static int iface_bind (int fd, int if_index, int protocol) {
    struct sockaddr_ll sll = {
        .sll_family = PF_PACKET,
        .sll_protocol = protocol,
        .sll_ifindex = if_index
    };

    if (bind (fd, (struct sockaddr *) &sll, sizeof (sll) ) < 0) {
        perror ("bind");
        return -1;
    }

    return 0;
}


static int iface_promiscuous (int fd, int if_index) {
    struct packet_mreq mr;
    memset (&mr, 0, sizeof (mr) );
    mr.mr_ifindex = if_index;
    mr.mr_type = PACKET_MR_PROMISC;

    if (setsockopt (fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof (mr) ) == -1) {
        perror ("setsockopt (failed to enter promiscuous mode)");
        return -1;
    }
    return 0;
}

static int iface_auxdata (int fd) {
    int            val = 1;

    if (setsockopt (fd, SOL_PACKET, PACKET_AUXDATA, &val, sizeof (val) ) == -1) {
        perror ("setsockopt (PACKET_AUXDATA)");
        return -1;
    }
    return 0;
}

static void preparing_data () {
    memset (&data->msg, 0, sizeof (data->msg) );
    data->msg.msg_iov = &data->iv;
    data->msg.msg_iovlen = 1;

    data->msg.msg_control = &data->control_un;
    data->msg.msg_controllen = sizeof (data->control_un);
    data->msg.msg_flags = 0;
}

static void pkt_receive (char *packet_buffer, size_t buffer_size, void (*callback) (int, ssize_t) ) {
    data->iv.iov_base = packet_buffer;
    data->iv.iov_len = buffer_size;

    ssize_t len = recvmsg (data->sockfd, &data->msg, MSG_TRUNC);

    int vlanid = 0;

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR (&data->msg); cmsg != NULL; cmsg = CMSG_NXTHDR (&data->msg, cmsg) ) {
        if (cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == PACKET_AUXDATA) {
            struct tpacket_auxdata *aux = (struct tpacket_auxdata *) CMSG_DATA (cmsg);

            vlanid = aux->tp_vlan_tci & 0xfff;
            break;
        }
    }

    callback (vlanid, len);
}

static int pkt_file_descriptor() {
    return data->sockfd;
}

struct linux_packet_t *new_linux_packet (const char *device) {
    while (self == NULL) {
        self = &singleton;
        data = &singleton_data;

        self->receive = pkt_receive;
        self->fileDescriptor = pkt_file_descriptor;

        uint16_t protocol = htons (ETH_P_ALL);
        int device_id = -1;
        int sockfd;

        if ( (sockfd = socket (PF_PACKET, SOCK_RAW, protocol) ) < 0) {
            perror ("socket");
            break;
        }

        if ( (device_id = iface_get_id (sockfd, device) ) < 0) {
            fprintf (stderr, "failed to get interface id: %s\n", device);
            break;
        }
        if (iface_bind (sockfd, device_id, protocol) < 0) {
            break;
        }

        iface_promiscuous (sockfd, device_id);
        iface_auxdata (sockfd);

        data->sockfd = sockfd;

        preparing_data();


        return self;
    }
    self = NULL;
    return NULL;
}
