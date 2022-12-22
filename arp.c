#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include "parser.h"
#include "arpguard.h"
#include "arpguard_db.h"
#include "utils.h"
#include "packet.h"

#define ETHWTYPE        1
#define ARPREQUEST        1
#define ARPREPLY        2

u_char full_packet[MAX_PACKET_LEN];
static struct ether_arphdr *pkt = (struct ether_arphdr *) &full_packet;
static int sockfd;
static short eth_p_arp;
struct in_addr *src_ip;
struct in_addr *tar_ip;

static void print_arprequest (void) {
    fprintf (logfp, "arp who-has %s tell %s (%s)\n",
             print_ip (pkt->target_ip),
             print_ip (pkt->sender_ip),
             print_ether (pkt->sender_eth));
}

void arp_atexit (void) {
    close (sockfd);
    pthread_exit (NULL);
}

static void arp_analyzer (int vlanid, ssize_t len) {
    int match_state;

    if (len < sizeof (struct ether_arphdr) || pkt->pkt_type != eth_p_arp) {
        if (verbose_flag > 5) {
            printf ("type: ( %x != %x), vlan: %d, packet size: %lu\n", pkt->pkt_type, eth_p_arp, vlanid, len);
        }
        return;
    }

    if (verbose_flag > 3) {
        printf ("vlan: %d, packet size: %lu\n", vlanid, len);
    }

    if (ntohs (pkt->arp_op) != ARPREQUEST) return;


//    if (vlanid <= 2000 || vlanid >= 3000) return;

    if (with_arpguard_network &&
            ((arpguard_netmask.s_addr & src_ip->s_addr)
             == arpguard_network.s_addr)) {

        if ((match_state = mydb_check_source_ip())
                == AGDB_EXACT_MATCH) {
            if (verbose_flag > 2) {
                fprintf (logfp, "In-table: ");
                print_arprequest();
            }
        } else {
            if (verbose_flag > 1) {
                fprintf (logfp, "Not in table: ");
                print_arprequest();
            }
        }
    } else {
        match_state = AGDB_NO_IN_RANGE;
        return;
    }

    mydb_write_source_mac_ip (3, match_state);
}

void arp_main (void) {
    src_ip = (struct in_addr *) pkt->sender_ip;
    tar_ip = (struct in_addr *) pkt->target_ip;


    if (listen_interface == NULL) {
        fprintf (stderr,
                 "listen on all network interfaces (Thread: %ld)\r\n",
                 pthread_self());
    } else {
        fprintf (stderr,
                 "listen on %s (Thread: %ld)\r\n",
                 listen_interface, pthread_self());
    }

    if (with_arpguard_network) {
        fprintf (logfp, "listen on %s netmask %s\n",
                 print_ip ((u_char * ) & arpguard_network),
                 print_ip ((u_char * ) & arpguard_netmask));

    }


    eth_p_arp = ntohs (ETH_P_ARP);

    struct linux_packet_t *linuxPacket = new_linux_packet (listen_interface);

    sockfd = linuxPacket->fileDescriptor();

    eth_p_arp = ntohs (ETH_P_ARP);
    src_ip = (struct in_addr *) pkt->sender_ip;
    tar_ip = (struct in_addr *) pkt->target_ip;


    if (sockfd < 0) {
        pthread_kill (main_thread, SIGTERM);

        pthread_exit (NULL);
    }

    fflush (logfp);

    while (!terminate) {
        linuxPacket->receive ((char *) full_packet, sizeof (full_packet), arp_analyzer);
    }

    return arp_atexit();
}
