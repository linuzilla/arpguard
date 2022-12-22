//
// Created by saber on 8/12/21.
//


#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <string.h>
#include <microhttpd.h>
#include <stdio.h>
#include <signal.h>
#include "arpguard.h"
#include "route.h"
#include "todo.h"

#define POST_METHOD "POST"

static struct route_t **routes;

static enum MHD_Result httpWriteContent (struct MHD_Connection *connection, const char *content) {
    struct MHD_Response *response;
    enum MHD_Result ret;

    response = MHD_create_response_from_buffer (strlen (content), (void *) content, MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
    MHD_destroy_response (response);

    return ret;
}

static enum MHD_Result routeHandler (void *cls, struct MHD_Connection *connection,
                                     const char *url, const char *method,
                                     const char *version, const char *upload_data, size_t *upload_data_size,
                                     void **con_cls) {
    char *pass = NULL;
    char *user = MHD_basic_auth_get_username_password (connection, &pass);

    if (user != NULL && pass != NULL) {
        printf ("[*] logged in as %s / %s\n", user, pass);
        MHD_free (user);
        MHD_free (pass);
    }

    for (struct route_t **r = routes; *r != NULL; r++) {
        // printf("[*] route %s\n", (*r)->pattern);

        pcre2_match_data *match_data = pcre2_match_data_create_from_pattern ((*r)->re, NULL);
        PCRE2_SPTR subject = (PCRE2_SPTR) url;

        int rc = pcre2_match (
                     (*r)->re,             /* the compiled pattern */
                     subject,              /* the subject string */
                     strlen (url),        /* the length of the subject */
                     0,                    /* start at offset 0 in the subject */
                     0,                    /* default options */
                     match_data,           /* block for storing the result */
                     NULL);                /* use default match context */

        if (rc <= 0) {
            pcre2_match_data_free (match_data); /* Release memory used for the match */
        } else {
//            printf ("Matched [%s] against %s\n", url, (*r)->pattern);

            PCRE2_SIZE *ovector = pcre2_get_ovector_pointer (match_data);

            char **args = (char **) malloc (rc * sizeof (char *));

            for (int i = 0; i < rc; i++) {
                PCRE2_SPTR substring_start = subject + ovector[2 * i];
                size_t substring_length = ovector[2 * i + 1] - ovector[2 * i];

                // printf ("%2d: %.*s (%d)\n", i, (int) substring_length, (char *) substring_start, (int) substring_length);

                * (args + i) = strndup ((char *) substring_start, substring_length);
            }
            char *content = (*r)->handleRequest (method, rc, args);

            for (int i = 0; i < rc; i++) {
                if (* (args + i) != NULL) free (* (args + i));
            }
            free (args);
            pcre2_match_data_free (match_data); /* Release memory used for the match */

            struct MHD_Response *response = MHD_create_response_from_buffer (strlen (content), (void *) content,
                                            MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header (response, "Content-Type", "application/json");

            return MHD_queue_response (connection, MHD_HTTP_OK, response);
        }
    }


    printf (">> New %s request for %s using version %s\n", method, url, version);

    const char *page = "<html><body>Hello, browser!</body></html>";

    return httpWriteContent (connection, page);
}

static char *return_success() {
    return "{ \"status\": \"success\" }";
}

static char *return_failure() {
    return "{ \"status\": \"failure\" }";
}

static char *default_handler (const char *method, int argc, char **argv) {
    return return_success();
}


static char *update_database (const char *method, int argc, char **argv) {
    if (strcmp (POST_METHOD, method) == 0) {
        todo_enqueue (ARP_TODO_UPDATE_DB);
        pthread_kill (main_thread, SIGUSR1);

        fprintf (logfp, "%s: Update Database\n", method);

        return return_success();
    } else {
        return return_failure();
    }
//    return MHD_YES;
}

static char *write_back (const char *method, int argc, char **argv) {
    if (strcmp (POST_METHOD, method) == 0) {
        todo_enqueue (ARP_TODO_WRITE_SQL);
        pthread_kill (main_thread, SIGUSR1);

        fprintf (logfp, "%s: Write back Database\n", method);

        return return_success();
    } else {
        return return_failure();
    }
}


int start_http_server (const int port, void (*callback) (void)) {
    struct MHD_Daemon *daemon;

    struct route_t *r[] = {
        route ("^/update$", update_database),
        route ("^/write$", write_back),
        route (".*", default_handler),
        NULL,
    };
    routes = r;

    printf ("httpd listen on port: %d\n", port);


    if ((daemon = MHD_start_daemon (MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD,
                                    port, NULL, NULL,
                                    routeHandler,
                                    NULL, MHD_OPTION_END)) != NULL) {
        callback();
        MHD_stop_daemon (daemon);
        return 0;
    }


    return -1;
}

