#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include "parser.h"
#include "arpguard.h"
#include "arpguard_db.h"
#include "utils.h"
#include "todo.h"

pthread_t		arp_thread   = 0;
pthread_t		main_thread  = 0;
pthread_mutex_t		pv_mutex     = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t		arp_mutex    = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t		arp_cond     = PTHREAD_COND_INITIALIZER;


char			*program_name	  = NULL;
volatile int		terminate = 0;
int			verbose_flag = 0;
int			debug_flag   = 0;
FILE			*logfp = NULL;

static sigset_t	sigs_todo;

void interrupt (int signal_no) {
    pthread_t	thread = pthread_self ();


    if (pthread_equal (main_thread, thread)) {
        fprintf (logfp, "Main thread capture signal %d\n",
                 signal_no);
        switch (signal_no) {
        case SIGCHLD:
        case SIGUSR1:
            break;
        case SIGTERM:
        case SIGINT:
        case SIGQUIT:
        case SIGHUP:
            terminate = 1;
            break;
        }
    } else if (pthread_equal (arp_thread, thread)) {
        fprintf (logfp, "ARP thread capture signal %d\n",
                 signal_no);

        terminate = 1;
        if (signal_no == SIGALRM) {
            fprintf (logfp, "Timeout\n");
            arp_atexit ();
        } else if (signal_no != SIGUSR1) {
            signal (SIGALRM,  interrupt);
            alarm (5);
        }
    }
}

static void main_loop (void) {
    int		signo, todo_action;

    while (! terminate) {
        sigwait (&sigs_todo, &signo);
        if (signo == SIGUSR1) {
            while ((todo_action = todo_dequeue ()) != -1) {
                switch (todo_action) {
                case ARP_TODO_UPDATE_DB:
                    fprintf (logfp,
                             "Update IP MAC table\n");
                    fflush (logfp);
                    update_static_ip_table_from_mysql ();
                    break;

                case ARP_TODO_WRITE_SQL:
                    fprintf (logfp,
                             "Update IP Mis-matched arp request\n");
                    fflush (logfp);
                    update_abuse_to_mysql ();
                    break;

                default:
                    fprintf (logfp, "todo %d\n",
                             todo_action);
                    fflush (logfp);
                    break;
                }
            }
        } else {
            terminate = 1;
        }
        // do_one_thing ();
        usleep (10);
    }
}

int main (int argc, char *argv[]) {
    char		*cp;
    char		*config_file = "/usr/local/etc/arpguard.conf";
    char		*log_file    = NULL;
    int		help_flag    = 0;
    int		c, i;
    int		option_index = 0;
    short		daemon_flag = 0;
    void		*status;

    struct option	long_options[] = {
        { "daemon"		, 0, 0, 'D' },
        { "verbose"		, 0, 0, 'v' },
        { "debug"		, 0, 0, 'd' },
        { "help"		, 0, 0, 'h' },
        { "config-file"		, 1, 0, 'f' },
        { "log-file"		, 1, 0, 'l' },
        { 0			, 0, 0,  0  }
    };

    program_name = ((cp = strrchr (argv[0], '/')) != NULL) ? cp + 1 : argv[0];

    fprintf (stderr, "\r\n"
             "%s v%s, Copyright (c) 2004, 2022 written by Mac Liu [ linuzilla@gmail.com ]\r\n\n",
             program_name, ARPGUARD_VERSION);

    fprintf (stderr, "Check machine\'s byte order: ");

    if (check_byte_ending () == -1) {
        fprintf (stderr, " ... good\r\n");
    } else {
        fprintf (stderr, " ... error\r\n");
        exit (0);
    }

    while ((c = getopt_long (argc, argv, "vDdhf:",
                             long_options, &option_index)) != EOF) {
        switch (c) {
        case 'v':
            verbose_flag++;
            break;
        case 'D':
            daemon_flag = 1;
            break;
        case 'd':
            debug_flag = 1;
            break;
        case 'h':
            help_flag = 1;
            break;
        case 'f':
            config_file = optarg;
            break;
        case 'l':
            log_file = optarg;
            break;
        case 0:
            exit (0);
            break;
        default:
        case '?':
            exit (0);
            break;
        }
    }

    for (i = optind; i < argc; i++) {
        printf ("[%s]\n", argv[i]);
    }

    if (help_flag) {
        printf ("%s [-options]\n"
                "\t-D (--daemon)\n"
                "\t-v (--verbose)\n"
                "\t-d (--debug)\n"
                "\t-h (--help)\n"
                "\t-f (--config-file)\n\n",
                program_name);
        exit (0);
    }


    fprintf (stderr, "Reading config file \"%s\" ... ", config_file);

    if ((yyin = fopen (config_file, "r")) != NULL) {
        int result = yyparse();
        fclose (yyin);

        if (result != 0) {
            fprintf (stderr, "error\r\n");
            exit (1);
        } else {
            fprintf (stderr, "ok\r\n");
        }
    } else {
        perror ("");
        exit (1);
    }

    if (log_file == NULL) log_file = sysconf_str ("log-file");

    if (log_file != NULL) {
        fprintf (stderr, "Setting output log to: %s ... ", log_file);
        if ((logfp = fopen (log_file, "w+")) != NULL) {
            fprintf (stderr, "ok\r\n");
        } else {
            perror ("");
            logfp = stderr;
        }
    } else {
        fprintf (stderr, "Setting output log to: STDERR\n");
        logfp = stderr;
    }

    if (! init_mysql_and_berkeley_db ()) {
        fprintf (logfp, "init mysql and berkeley db failed\r\n");
        exit (1);
    }

    /*
    if ((key = sysconf_get_first_key ()) != NULL) {
    	do {
    		printf ("key [%s][%s]\n", key,
    			sysconf_str (key)
    					);
    	} while ((key = sysconf_get_next_key ()) != NULL);
    }
    */

    // allocate a buffer for static IP table
    // use DB as a hash for mapping of last MAC mapping

    if (daemon_flag) {
        if (fork () > 0) exit (0);

        setsid ();
        if (chdir ("/") != 0) {
            perror ("chdir");
        }
        close (0);
        close (1);
        close (2);
        // umask (002);
    }

    main_thread = pthread_self ();

    signal (SIGINT,  interrupt);
    signal (SIGTERM, interrupt);
    signal (SIGQUIT, interrupt);
    signal (SIGCHLD, interrupt);
    signal (SIGUSR1, interrupt);
    signal (SIGHUP, SIG_IGN);

    sigemptyset (&sigs_todo);
    sigaddset   (&sigs_todo, SIGUSR1);
    sigaddset   (&sigs_todo, SIGTERM);
    sigaddset   (&sigs_todo, SIGINT);
    sigaddset   (&sigs_todo, SIGQUIT);

    pthread_create (&arp_thread,  NULL, (void *) arp_main, NULL);

    /*
    pthread_mutex_lock   (&arp_mutex);
    pthread_cond_signal  (&arp_cond);
    pthread_mutex_unlock (&arp_mutex);
    */

    start_http_server (sysconf_int ("http-port"), main_loop);

    pthread_kill (arp_thread,  SIGTERM);
    fprintf (logfp, "ok.\n");

    pthread_join (arp_thread,  &status);

    finialize_mysql_and_berkeley_db ();

    fflush (logfp);
    fclose (logfp);

    return 0;
}
