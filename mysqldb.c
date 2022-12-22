#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <db.h>
#include <pthread.h>
#include <mysql/mysql.h>
#include "arpguard.h"
#include "arpguard_db.h"
#include "parser.h"
#include "utils.h"
#include "pthread_rwlock.h"

int		enable_mysql = 0;
int		in_update_mysql_db = 0;
int		enable_mysql_update = 0;

static DB	*dbip = NULL;
static DB	*dbmc = NULL;
static DB	*dbim = NULL;
static DBT	dbt_srcip, dbt_srcmc, dbt_ikey, dbt_mkey;
static DBT	dbt_imkey, dbt_imdata;

static char	localbuffer[1024];
static DBT	dbt_lb;

static struct db_arp_mac_entry		dbme_srcmc;
static struct db_arp_ip_entry		dbie_srcip;
static struct db_arp_ip_mac_key_entry	dbim_key;
static struct db_arp_ip_mac_data_entry	dbim_data;

//static pthread_mutex_t	mysqldb_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_rdwr_t		rwmutex;

// static pthread_rwlock_t		mysqldb_rwlock;

static struct arp_ip_entry	*arp_ip_table = NULL;
static int			number_of_arp_ip_table = 0;
static u_char			*sender_ip = NULL, *sender_mac = NULL;
static u_char			*target_ip = NULL, *target_mac = NULL;

// use for fast transfer
static u_int32_t		*ft32_srcip, *ft32_dstip;
static u_int64_t		*ft64_srcmc, *ft64_dstmc;
static struct in_addr		*inaddr_srcip;

static char			*mysql_reading_query = NULL;
static char			*mysql_update_query = NULL;

static void init_berkeley_db_data (void);
static int  reopen_berkeley_db    (void);


int init_mysql_and_berkeley_db (void) {
    struct in_addr		mask;
    struct ether_arphdr	*pkt = (struct ether_arphdr *) full_packet;

    // pthread_rdwr_init_np (&rwmutex, NULL);

    init_berkeley_db_data ();

    if (! reopen_berkeley_db ()) return 0;

    // initialize input data
    sender_ip = pkt->sender_ip; sender_mac = pkt->sender_eth;
    target_ip = pkt->target_ip; target_mac = pkt->target_eth;

    mask.s_addr = inet_addr ("255.255.255.255");


    if (with_arpguard_network) {
        fprintf (logfp, "network %s ",
                 inet_ntoa (arpguard_network));
        fprintf (logfp, "netmask %s",
                 inet_ntoa (arpguard_netmask));

        number_of_arp_ip_table =
            ntohl (mask.s_addr ^ arpguard_netmask.s_addr) + 1;

        arp_ip_table = calloc (number_of_arp_ip_table,
                               sizeof (struct arp_ip_entry));

        if (arp_ip_table == NULL) {
            fprintf (logfp, "\n");
            perror ("calloc");
            return 0;
        } else {
            int	i;

            for (i = 0; i < number_of_arp_ip_table; i++) {
                arp_ip_table[i].inuse   = 0;
                arp_ip_table[i].lastuse = 0;
            }

            fprintf (logfp, " ... %d IP buffer allocated\n",
                     number_of_arp_ip_table);
        }
    }

    if (sysconf_int ("enable-mysql") == 0) {
        fprintf (logfp, "MySQL client version %s (disable)\n",
                 mysql_get_client_info ());
        enable_mysql = 0;
        return 1;
    } else {
        enable_mysql = 1;
    }

    if ((mysql_update_query = sysconf_str ("mysql-update")) != NULL) {
        if (strlen (mysql_update_query) > 1024) {
            fprintf (logfp,
                     "string too long ... disable mysql-update\n");
            enable_mysql_update = 0;
            mysql_update_query = NULL;
        } else {
            enable_mysql_update = 1;
        }
    }

    if ((mysql_reading_query = sysconf_str ("mysql-query")) != NULL) {
        if (strlen (mysql_reading_query) > 1024) {
            fprintf (logfp,
                     "string too long ... disable mysql-update\n");
            mysql_reading_query = "SELECT ip,mac FROM `iparp`";
        }
    }

    return update_static_ip_table_from_mysql ();
}

void finialize_mysql_and_berkeley_db (void) {
    if (dbip != NULL) {
        dbip->close (dbip, 0);
        dbip = NULL;
    }
    if (dbmc != NULL) {
        dbmc->close (dbmc, 0);
        dbmc = NULL;
    }
    if (dbim != NULL) {
        dbim->close (dbim, 0);
        dbim = NULL;
    }
}

void mydb_dump (void) {
    DBC				*cursorp = NULL;
    DBT				key, data;
    char				keybuffer [1024];
    char				databuffer[1024];
    struct db_arp_mac_entry		*mptr = (void *) databuffer;
    struct db_arp_ip_entry		*iptr = (void *) databuffer;
    time_t				*tptr;


    bzero (&key,  sizeof (DBT));
    bzero (&data, sizeof (DBT));

    key.data	= keybuffer;
    key.size	= key.ulen = sizeof keybuffer;
    key.flags	= DB_DBT_USERMEM;

    data.data	= databuffer;
    data.size	= data.ulen = sizeof databuffer;
    data.flags	= DB_DBT_USERMEM;


    if (dbip->cursor (dbip, NULL, &cursorp, 0) == 0) {
        tptr = &iptr->lastuse;

        if (cursorp->c_get (cursorp, &key, &data, DB_FIRST) == 0) {
            do {
                fprintf (logfp, "%-20s %-20s%s",
                         print_ip ((const u_char *) keybuffer),
                         print_ether (iptr->x.mac),
                         ctime (tptr));
            } while (cursorp->c_get
                     (cursorp, &key, &data, DB_NEXT) == 0);
        }
    }

    if (dbmc->cursor (dbmc, NULL, &cursorp, 0) == 0) {
        tptr = &mptr->lastuse;

        if (cursorp->c_get (cursorp, &key, &data, DB_FIRST) == 0) {
            do {
                fprintf (logfp, "%-20s %-20s%s",
                         print_ether ((const u_char *) keybuffer),
                         print_ip ((const u_char *) &mptr->ip),
                         ctime (tptr));
            } while (cursorp->c_get
                     (cursorp, &key, &data, DB_NEXT) == 0);
        }
    }
}

int mydb_check_source_ip (void) {
    static const u_int64_t	mask = 0xffffffffffffLL;
    int			idx;
    int			retval;
    // u_int64_t		mac;

    // pthread_rdwr_rlock_np (&rwmutex);

    idx = ntohl (arpguard_network.s_addr ^ inaddr_srcip->s_addr);

    if (arp_ip_table[idx].inuse > 0) {
        if (arp_ip_table[idx].x.mval == (*ft64_srcmc & mask)) {
            retval = AGDB_EXACT_MATCH;
        } else {
            retval = AGDB_NOT_MATCH;
        }
    } else {
        retval = AGDB_NO_IN_TABLE;
    }

    // pthread_rdwr_runlock_np (&rwmutex);

    return retval;
}

int update_static_ip_table_from_mysql (void) {
    MYSQL		*mysql_conn;
    int		res;
    int		retval = 1;

    if (! with_arpguard_network) return 0;
    if (! enable_mysql) return 0;

    // pthread_mutex_lock (&mysqldb_mutex);

    pthread_rdwr_wlock_np (&rwmutex);

    in_update_mysql_db++;

    if (! (mysql_conn = mysql_init (NULL))) {
        fprintf (logfp, "mysql_init failed\n");
        retval = 0;
    } else if (! (mysql_conn = mysql_real_connect ( mysql_conn,
                               sysconf_str ("mysql-server"),
                               sysconf_str ("mysql-account"),
                               sysconf_str ("mysql-passwd"),
                               sysconf_str ("mysql-database"),
                               0, NULL, 0))) {
        fprintf (logfp, "Connect to mysql server failed\n");
        retval = 0;
    } else if ((res = mysql_query (mysql_conn, mysql_reading_query))) {
        fprintf (logfp, "%s\n", mysql_error (mysql_conn));
        retval = 0;
    } else {
        MYSQL_RES	*res_ptr;
        MYSQL_ROW	sqlrow;
        int		i, j;


        fprintf (logfp, "Connect to MySQL server \"%s\": ",
                 sysconf_str ("mysql-server"));

        fprintf (logfp, "ok\n"
                 "MySQL server:%s / client:%s\n",
                 mysql_get_server_info (mysql_conn),
                 mysql_get_client_info ());

        for (i = 0; i < number_of_arp_ip_table; i++) {
            if (arp_ip_table[i].inuse == 1) {
                arp_ip_table[i].inuse = 2;
            } else {
                arp_ip_table[i].inuse = 0;
            }
            arp_ip_table[i].lastuse = 0;
        }

        if ((res_ptr = mysql_store_result (mysql_conn))) {
            u_char		*macbuffer;
            int		v;
            unsigned long	idx;
            struct in_addr	ipbuffer;
            int		effected_rows = 0;

            reopen_berkeley_db ();

            fprintf (logfp, "Retrieved %lu row(s) ... ",
                     (unsigned long) mysql_num_rows (res_ptr));

            while ((sqlrow = mysql_fetch_row (res_ptr))) {
                ipbuffer.s_addr = inet_addr (sqlrow[0]);

                if ((arpguard_netmask.s_addr & ipbuffer.s_addr)
                        == arpguard_network.s_addr) {

                    idx = ntohl (arpguard_network.s_addr ^
                                 ipbuffer.s_addr);

                    effected_rows++;
                    /*
                    printf ("%5lu. %s\n",
                    		idx,
                    		inet_ntoa (ipbuffer));
                    		*/
                } else {
#if DEBUG
                    fprintf (logfp, "%s: not in subnet\n",
                             inet_ntoa (ipbuffer));
#endif
                    continue;
                }

                macbuffer = arp_ip_table[idx].x.mac;
                arp_ip_table[idx].inuse = 1;

                for (i = 0; i < 6; i++) {
                    for (v = 0, j = i * 2; j <= i * 2 + 1; j++) {
                        v *= 16;

                        if ((sqlrow[1][j] >= '0') &&
                                (sqlrow[1][j] <= '9')) {
                            v += sqlrow[1][j] - '0';
                        } else if ((sqlrow[1][j] >= 'a')
                                   && (sqlrow[1][j] <= 'f')) {
                            v += (sqlrow[1][j]
                                  - 'a' + 10);
                        } else if ((sqlrow[1][j] >= 'A')
                                   && (sqlrow[1][j] <= 'F')) {
                            v += (sqlrow[1][j]
                                  - 'A' + 10);
                        }
                    }
                    macbuffer[i] = v;
                }
            }

            fprintf (logfp, "%d row(s) effective\n",
                     effected_rows);
        }

        for (i = 0; i < number_of_arp_ip_table; i++) {
            if (arp_ip_table[i].inuse == 2)
                arp_ip_table[i].inuse = 0;
        }
    }
    mysql_close (mysql_conn);

    in_update_mysql_db--;
    pthread_rdwr_wunlock_np (&rwmutex);
    // pthread_mutex_unlock (&mysqldb_mutex);

    return retval;
}

int update_abuse_to_mysql (void) {
    DBC					*cursorp = NULL;
    DBT					key, data;
    struct db_arp_ip_mac_key_entry		imkey;
    struct db_arp_ip_mac_data_entry		imdata;
    MYSQL					*mysql_conn;
    int					retval;

    if (! enable_mysql) return 0;

    if (dbim->cursor (dbim, NULL, &cursorp, 0) != 0) return 0;

    bzero (&key,  sizeof (DBT));
    bzero (&data, sizeof (DBT));

    key.data   = (void *) &imkey;
    key.size   = key.ulen = sizeof (imkey);
    key.flags  = DB_DBT_USERMEM;

    data.data  = (void *) &imdata;
    data.size  = data.ulen = sizeof (imdata);
    data.flags = DB_DBT_USERMEM;

    pthread_rdwr_rlock_np (&rwmutex);

    if (! (mysql_conn = mysql_init (NULL))) {
        retval = 0;
    } else if (! (mysql_conn = mysql_real_connect (mysql_conn,
                               sysconf_str ("mysql-server"),
                               sysconf_str ("mysql-account"),
                               sysconf_str ("mysql-passwd"),
                               sysconf_str ("mysql-database"),
                               0, NULL, 0))) {
        retval = 0;
    } else {
        char		query[4096];

        if (cursorp->c_get (cursorp, &key, &data, DB_FIRST) == 0) {
            do {
                u_char *lastUse = timet_2_mysql_datetime (&imdata.lastuse);

                sprintf (query, mysql_update_query,
                         print_ip  ((const u_char *) &imkey.ip),
                         print_mac (imkey.x.mac),
                         timet_2_mysql_datetime (&imdata.firstuse),
                         lastUse,
                         lastUse);

                mysql_query (mysql_conn, query);
                // fprintf (logfp, "%s\n", query);
            } while (cursorp->c_get (cursorp, &key,
                                     &data, DB_NEXT) == 0);
        }

        retval = 1;
    }
    mysql_close (mysql_conn);
    pthread_rdwr_runlock_np (&rwmutex);
    return retval;
}

void mydb_write_source_mac_ip (const int mask, const int match) {
    static const u_int64_t	macmask = 0xffffffffffffLL;

    // a fast copy
    *ft32_dstip = *ft32_srcip;
    *ft64_dstmc = *ft64_srcmc & macmask;

    time (&dbie_srcip.lastuse);
    time (&dbme_srcmc.lastuse);

    pthread_rdwr_rlock_np (&rwmutex);

    if ((mask & 1) != 0) dbmc->put (dbmc, NULL, &dbt_mkey, &dbt_srcmc, 0);
    if ((mask & 2) != 0) dbip->put (dbip, NULL, &dbt_ikey, &dbt_srcip, 0);

    if (match != AGDB_EXACT_MATCH) {
        dbim_key.x.mval    = *ft64_dstmc;
        dbim_key.ip.s_addr = *ft32_dstip;

        if (dbim->get (dbim, NULL, &dbt_imkey, &dbt_imdata, 0) != 0) {
            time (&dbim_data.firstuse);
        }

        time (&dbim_data.lastuse);
        dbim->put (dbim, NULL, &dbt_imkey, &dbt_imdata, 0);
    }

    pthread_rdwr_runlock_np (&rwmutex);
}

int mydb_get_ipaddress (const u_char *mac, struct db_arp_mac_entry *dbme) {
    DBT	dbt_mac, dbt_data;
    int	retval;

    bzero (&dbt_mac,  sizeof (DBT));
    bzero (&dbt_data, sizeof (DBT));

    dbt_mac.data   = (void *) mac;
    dbt_mac.size   = dbt_mac.ulen = 6;
    dbt_mac.flags  = DB_DBT_USERMEM;

    dbt_data.data  = (void *) dbme;
    dbt_data.size  = dbt_data.ulen = sizeof (struct db_arp_mac_entry);
    dbt_data.flags = DB_DBT_USERMEM;

    pthread_rdwr_rlock_np (&rwmutex);
    retval = dbmc->get (dbmc, NULL, &dbt_mac, &dbt_data, 0);
    pthread_rdwr_runlock_np (&rwmutex);

    return retval;
}

int mydb_get_macaddress (const u_int32_t ip, struct db_arp_ip_entry *dbie) {
    DBT	dbt_ip, dbt_data;
    int	retval;

    bzero (&dbt_ip,   sizeof (DBT));
    bzero (&dbt_data, sizeof (DBT));

    dbt_ip.data    = (void *) &ip;
    dbt_ip.size    = dbt_ip.ulen = sizeof (u_int32_t);
    dbt_ip.flags   = DB_DBT_USERMEM;

    dbt_data.data  = (void *) dbie;
    dbt_data.size  = dbt_data.ulen = sizeof (struct db_arp_ip_entry);
    dbt_data.flags = DB_DBT_USERMEM;

    pthread_rdwr_rlock_np (&rwmutex);
    retval = dbip->get (dbip, NULL, &dbt_ip, &dbt_data, 0);
    pthread_rdwr_runlock_np (&rwmutex);

    return retval;
}

static void init_berkeley_db_data (void) {
    struct ether_arphdr	*pkt = (struct ether_arphdr *) full_packet;


    fprintf (logfp, "%s\n", db_version (NULL, NULL, NULL));

    bzero (&dbt_srcip,  sizeof (DBT));
    bzero (&dbt_srcmc,  sizeof (DBT));
    bzero (&dbt_ikey,   sizeof (DBT));
    bzero (&dbt_mkey,   sizeof (DBT));

    bzero (&dbt_imkey,  sizeof (DBT));
    bzero (&dbt_imdata, sizeof (DBT));

    bzero (&dbt_lb,     sizeof (DBT));

    dbt_lb.data      = localbuffer;
    dbt_lb.size      = dbt_lb.ulen = 1024;
    dbt_lb.flags     = DB_DBT_USERMEM;

    dbt_ikey.data    = pkt->sender_ip;
    dbt_ikey.size    = dbt_ikey.ulen = 4;
    dbt_ikey.flags   = DB_DBT_USERMEM;

    dbt_mkey.data    = pkt->sender_eth;
    dbt_mkey.size    = dbt_mkey.ulen = 6;
    dbt_mkey.flags   = DB_DBT_USERMEM;

    dbt_srcip.data   = &dbie_srcip;
    dbt_srcip.size   = dbt_srcip.ulen = sizeof (struct db_arp_ip_entry);
    dbt_srcip.flags  = DB_DBT_USERMEM;

    dbt_srcmc.data   = &dbme_srcmc;
    dbt_srcmc.size   = dbt_srcmc.ulen = sizeof (struct db_arp_mac_entry);
    dbt_srcmc.flags  = DB_DBT_USERMEM;

    dbt_imkey.data   = &dbim_key;
    dbt_imkey.size   = dbt_imkey.ulen = sizeof (dbim_key);
    dbt_imkey.flags  = DB_DBT_USERMEM;

    dbt_imdata.data  = &dbim_data;
    dbt_imdata.size  = dbt_imdata.ulen = sizeof (dbim_data);
    dbt_imdata.flags = DB_DBT_USERMEM;

    ft32_srcip = (u_int32_t *) pkt->sender_ip;
    ft64_srcmc = (u_int64_t *) pkt->sender_eth;
    ft32_dstip = (u_int32_t *) &dbme_srcmc.ip;
    ft64_dstmc = (u_int64_t *) dbie_srcip.x.mac;

    inaddr_srcip = (struct in_addr *) pkt->sender_ip;
}

static int reopen_berkeley_db (void) {
    if (dbip != NULL) {
        dbip->close (dbip, 0);
        dbip = NULL;
    }
    if (dbmc != NULL) {
        dbmc->close (dbmc, 0);
        dbmc = NULL;
    }
    if (dbim != NULL) {
        dbim->close (dbim, 0);
        dbim = NULL;
    }

    if (db_create (&dbip, NULL, 0) != 0) {
        perror ("db_create");
        return 0;
    } else if (dbip->open (dbip, NULL, NULL, NULL, DB_HASH, DB_CREATE, 0666) != 0) {
        perror ("DB->open");
        return 0;
    }

    if (db_create (&dbmc, NULL, 0) != 0) {
        perror ("db_create");
        return 0;
    } else if (dbmc->open (dbmc, NULL, NULL, NULL, DB_HASH, DB_CREATE, 0666) != 0) {
        perror ("DB->open");
        return 0;
    }

    if (db_create (&dbim, NULL, 0) != 0) {
        perror ("db_create");
        return 0;
    } else if (dbim->open (dbim, NULL, NULL, NULL, DB_HASH, DB_CREATE, 0666) != 0) {
        perror ("DB->open");
        return 0;
    }

    return 1;
}
