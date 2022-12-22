%{

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "parser.h"
#include "y.tab.h"

int     lineno = 1;
char    linebuf[512];

%}

ws		[ \t]+
comment		\/\/.*|#.*
ipstring	[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}
macstring	([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}
id		[_a-zA-Z][\-_a-zA-Z0-9]*
string		\"[^\"\n]*\"

%%

{ws}			/* do nothing */ ;
{comment}		/* do nothing */ ;
^.*			{ strncpy (linebuf, yytext, 511); yyless(0); }
\n			{ lineno++;                  }
\x1a|\r			{ /* *** ignore *** */       }
listen                  { return RW_LISTEN;          }
proxy-arp		{ return RW_PROXYARP;	     }
network                 { return RW_NETWORK;         }
netmask                 { return RW_NETMASK;         }
with			{ return RW_WITH;            }
on			{ return RW_FLAG_ON;         }
off			{ return RW_FLAG_OFF;        }
{ipstring}		{ yylval = strdup(yytext); return IPSTRING;   }
{macstring}		{ yylval = strdup(yytext); return MACSTRING;  }
{id}			{ yylval = strdup(yytext); return IDENTIFIER; }
{string}		{ yylval = strdup(yytext); return QSTRING;    }
[0-9]+			{ yylval = strdup(yytext); return DIGIT;      }
.			{ return yytext[0];       }

%%

void yyerror(const char *msg) {
    fprintf(stderr, "line %d: %s: %s\n", lineno, msg, linebuf);
}
