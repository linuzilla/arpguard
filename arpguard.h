#ifndef __ARPGUARD_H_
#define __ARPGUARD_H_

#include <sys/types.h>
#include <pthread.h>

#define ARPGUARD_VERSION	"1.0.0"
#define MAX_PACKET_LEN		1800

struct ether_arphdr {
    u_char 		dst_mac[6], src_mac[6];
    u_short		pkt_type;
    u_short		hw_type, pro_type;
    u_char		hw_len, pro_len;
    u_short		arp_op;
    u_char		sender_eth[6], sender_ip[4];
    u_char		target_eth[6], target_ip[4];
};

extern char		*program_name;
extern u_char		full_packet[];
extern pthread_t	arp_thread;
extern pthread_t	snmp_thread;
extern pthread_t	main_thread;
extern pthread_mutex_t	arp_mutex;
extern pthread_cond_t	arp_cond;
extern pthread_mutex_t	snmp_mutex;
extern pthread_cond_t	snmp_cond;
extern volatile int	terminate;
extern int		verbose_flag;
extern int		debug_flag;
extern FILE		*logfp;

// extern volatile int	snmp_agent_terminate;

void	snmp_main  (void);
void	arp_main   (void);
void	arp_atexit (void);
int start_http_server (const int port, void (*callback) (void) );

#endif
