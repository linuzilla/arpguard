#ifndef __ARPGUARD_DB_H_
#define __ARPGUARD_DB_H_

#include <sys/types.h>
#include <netinet/in.h>

#define AGDB_EXACT_MATCH	1
#define AGDB_NOT_MATCH		2
#define AGDB_NO_IN_TABLE	3
#define AGDB_NO_IN_RANGE	4


struct arp_ip_entry {
    union {
        u_char		mac[8];
        u_int64_t	mval;
    } x;
    short int	inuse;
    time_t		lastuse;
};

struct db_arp_mac_entry {
    struct in_addr	ip;
    time_t		lastuse;
};

struct db_arp_ip_entry {
    union {
        u_char		mac[8];
        u_int64_t	mval;
    } x;
    time_t		lastuse;
};

struct db_arp_ip_mac_key_entry {
    struct in_addr	ip;
    union {
        u_char		mac[8];
        u_int64_t	mval;
    } x;
};

struct db_arp_ip_mac_data_entry {
    time_t			firstuse;
    time_t			lastuse;
};

int		enable_mysql;
int		in_update_mysql_db;

int	init_mysql_and_berkeley_db (void);
void	finialize_mysql_and_berkeley_db (void);

int	update_static_ip_table_from_mysql (void);
int	update_abuse_to_mysql (void);
int	mydb_check_source_ip (void);
void	mydb_write_source_mac_ip (const int mask, const int match);
void	mydb_dump (void);

int	mydb_get_macaddress (const u_int32_t ip, struct db_arp_ip_entry *dbie);
int	mydb_get_ipaddress (const u_char *mac, struct db_arp_mac_entry *dbme);

#endif
