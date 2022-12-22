#ifndef __PARSER_H_
#define __PARSER_H_

#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>

typedef char *  char_ptr;
#define YYSTYPE char_ptr
#define YY_NO_UNPUT

#define MAX_IPMASK	(1024)

typedef unsigned short       u_int16;
typedef unsigned int         u_int32;
typedef unsigned long long   u_int64;

extern FILE     *yyin;
extern void     yyerror (const char *);
extern int      yylex   (void);
extern int      yydebug;
extern int      yyparse (void);
extern YYSTYPE	yylval;

extern char *	sysconf_str (const char *key);
extern int	sysconf_int (const char *key);
extern char *	sysconf_get_first_key (void);
extern char *	sysconf_get_next_key  (void);

extern u_int32	ipmask_mask [];

extern char		*listen_interface;
extern struct in_addr	arpguard_network;
extern struct in_addr	arpguard_netmask;
extern struct in_addr	proxyarp_network;
extern struct in_addr	proxyarp_netmask;
extern u_char		proxyarp_mac[6];
extern int		with_arpguard_network;
extern int		with_proxyarp_network;

#endif
