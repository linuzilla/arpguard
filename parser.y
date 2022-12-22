%{
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include "parser.h"
#include "utils.h"


int			with_arpguard_network = 0;
int			with_proxyarp_network = 0;
char			*listen_interface = NULL;
struct in_addr		arpguard_network;
struct in_addr		arpguard_netmask;
struct in_addr		proxyarp_network;
struct in_addr		proxyarp_netmask;
u_char			proxyarp_mac[6];

struct sysconf_entry_t {
        char                    *key;
        int                     ivalue;
        char                    *value;
        struct sysconf_entry_t  *next;
};

static struct sysconf_entry_t	  sysconf_entry   = { NULL, -1, NULL, NULL };
static struct sysconf_entry_t	* sysconf_ptr (const char *key);
static struct sysconf_entry_t	* sysconf_key_pointer = NULL;

static void*	addentry_integer(const char *entry, const char *value);
static void*	addentry_string	(const char *entry, const char *value);
static void*	addentry_ip	(const char *entry, const char *value);
static void*	addentry_mac	(const char *entry, const char *value);
static void*	addentry_flag_on  (const char *entry);
static void*	addentry_flag_off (const char *entry);
static char	*strip_qstring	(const char *qst);

%}

%token RW_LISTEN   RW_NETWORK  RW_NETMASK
%token RW_PROXYARP RW_WITH     RW_FLAG_ON    RW_FLAG_OFF
%token IDENTIFIER  DIGIT       IPSTRING      MACSTRING	   QSTRING  FQSTRING
%token '=' ';'

%%

full_definition		: system_definitions
			;

system_definitions	: system_definition
			| system_definition system_definitions
			;

system_definition	: listen_definition
			| interface_definition
			| proxyarp_definition
			| variable_definition
			;

variable_definition	: IDENTIFIER '=' DIGIT ';'
			  { addentry_integer ($1, $3); }
			| IDENTIFIER '=' QSTRING ';'
			  { addentry_string  ($1, $3); }
			| IDENTIFIER '=' IPSTRING ';'
			  { addentry_ip      ($1, $3); }
			| IDENTIFIER '=' MACSTRING ';'
			  { addentry_mac     ($1, $3); }
			| IDENTIFIER '=' RW_FLAG_ON  ';'
			  { addentry_flag_on  ($1); }
			| IDENTIFIER '=' RW_FLAG_OFF ';'
			  { addentry_flag_off ($1); }
			;

listen_definition	: RW_LISTEN RW_NETWORK IPSTRING RW_NETMASK IPSTRING ';'
                          {
				arpguard_network.s_addr = inet_addr ($3);
				arpguard_netmask.s_addr = inet_addr ($5);

				with_arpguard_network = 1;
                          }
			;

interface_definition	: RW_LISTEN RW_FLAG_ON QSTRING ';'
			  {
				listen_interface = strdup (strip_qstring ($3));
			  }

proxyarp_definition	: RW_PROXYARP RW_NETWORK IPSTRING
			  RW_NETMASK IPSTRING RW_WITH MACSTRING ';'
			{
				// printf ("proxyarp %s %s %s\n", $3, $5, $7);
				proxyarp_network.s_addr = inet_addr ($3);
				proxyarp_netmask.s_addr = inet_addr ($5);
				if (text2macaddr ($7, proxyarp_mac) != NULL) {
					with_proxyarp_network = 1;
				}
			}
			;
%%


char * sysconf_str (const char *key) {
        struct sysconf_entry_t  *ptr;

        if ((ptr = sysconf_ptr (key)) != NULL) return ptr->value;
        return NULL;
}

int sysconf_int (const char *key) {
        struct sysconf_entry_t  *ptr;

        if ((ptr = sysconf_ptr (key)) != NULL) return ptr->ivalue;
        return -1;
}

char * sysconf_get_first_key (void) {
	if ((sysconf_key_pointer = sysconf_entry.next) == NULL) return NULL;

	return sysconf_key_pointer->key;
}

char * sysconf_get_next_key (void) {
	if (sysconf_key_pointer == NULL) return NULL;

	if ((sysconf_key_pointer = sysconf_key_pointer->next) == NULL)
		return NULL;

	return sysconf_key_pointer->key;
}

////////////////////////////////////////////////////////////

static void* addentry_integer (const char *entry, const char *value) {
        int                     data;
        struct sysconf_entry_t  *ptr;

        data = atoi (value);

        if ((ptr = addentry_string (entry, value)) != NULL) ptr->ivalue = data;

        return ptr;
}

static void* addentry_string (const char *entry, const char *value) {
        struct sysconf_entry_t  *ptr;

        if ((ptr = malloc (sizeof (struct sysconf_entry_t))) != NULL) {
                ptr->key    = strdup (entry);
                if (value[0] == '"') {
                        ptr->value  = strdup (strip_qstring(value));
                } else {
                        ptr->value  = strdup (value);
                }
                ptr->ivalue = -1;
                ptr->next   = sysconf_entry.next;

                sysconf_entry.next = ptr;
        }
        return ptr;
}

static void* addentry_ip (const char *entry, const char *value) {
	return addentry_string (entry, value);
}

static void* addentry_mac (const char *entry, const char *value) {
	return addentry_string (entry, value);
}

static void* addentry_flag_on (const char *entry) {
        struct sysconf_entry_t  *ptr;

        if ((ptr = addentry_string (entry, "on")) != NULL) ptr->ivalue = 1;

        return ptr;
}

static void* addentry_flag_off (const char *entry) {
        struct sysconf_entry_t  *ptr;

        if ((ptr = addentry_string (entry, "off")) != NULL) ptr->ivalue = 0;

        return ptr;
}


static char *strip_qstring (const char *qst) {
        static char     buffer[4096];
        int             len;

        buffer[0] ='\0';
        strncpy (buffer, &qst[1], 4095);
        if ((len = strlen (buffer)) > 1) buffer[len-1] = '\0';

        return buffer;
}

static struct sysconf_entry_t * sysconf_ptr (const char *key) {
        struct sysconf_entry_t  *ptr = &sysconf_entry;

        while ((ptr = ptr->next) != NULL) {
                if (strcasecmp (key, ptr->key) == 0) {
                        return ptr;
                }
        }
        return NULL;
}

int yywrap (void) { return 1; }
