#

MYSQL_CONFIG = /usr/bin/mysql_config
ifeq ("$(wildcard $(MYSQL_CONFIG))","")
    MYSQL_CONFIG = mariadb_config
endif

CC	= gcc
CCOPT	= -Wall -O2 -g
INCLS   = -DYYDEBUG=1
DEFS    =
LOPT    =

LOPT   += -lpthread
LOPT   += -ldb
LOPT   += -lpcre2-8
LOPT   += -lmicrohttpd

CFLAGS = $(CCOPT) $(INCLS) $(DEFS) $(OSDEPOPT)
CFLAGS += $(shell $(MYSQL_CONFIG) --cflags)
LOPT +=  $(shell $(MYSQL_CONFIG)  --libs)

SRC = main.c arp.c packet.c mysqldb.c utils.c pthread_rwlock.c todo.c route.c http.c
OBJ = $(SRC:.c=.o)
VER := $(shell grep "^\#define ARPGUARD_VERSION" arpguard.h | awk '{print $$3}' |sed s:\"::g)
LEXYACCTMP = lex.yy.c y.tab.c y.tab.h y.output y.tab.o lex.yy.o
CLEANFILES = $(OBJ) arpguard $(LEXYACCTMP)
GCCVER := $(shell gcc -v 2>&1 | grep "gcc version" | awk '{print $$3}')
OSREL  := $(shell uname -r | sed 's/\([.0-9]*\).*/\1/')
# CFLAGS += -DGCC_VERSION=\"$(GCCVER)\" -DOS_RELEASE=\"$(OSREL)\"
# CFLAGS += -DCHIPLINUX_VERSION=\"$(VER)\"

.c.o:
	@rm -f $@
	$(CC) $(CFLAGS) -c $*.c

all: arpguard

arpguard:	$(OBJ) lex.yy.c  y.tab.c
	@rm -f $@
	$(CC) $(CFLAGS) -Wno-unused-function -s -o $@ $(OBJ) lex.yy.c y.tab.c $(LOPT)

lex.yy.c:	lexer.l
	flex lexer.l

y.tab.c:	parser.y
	bison -v -t -d -y parser.y

clean:
	rm -f $(CLEANFILES)
