#ifndef _LIUJC_UTILS_H_
#define _LIUJC_UTILS_H_

u_char * text2macaddr (const char *str, u_char *macaddr);
u_char * print_ether  (const u_char *mac);
u_char * print_mac    (const u_char *mac);
u_char * print_ip     (const u_char *ipstr);
u_char * timet_2_mysql_datetime (const time_t *ptr);
int	 check_byte_ending (void);


#endif
