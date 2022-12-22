//
// Created by saber on 8/12/21.
//

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <regex.h>
#include <microhttpd.h>
#include "route.h"

struct data {
    const char *pattern;
    const regex_t re;

};

//static char * request_handler (const char *method, int argc, char **argv) {
//    for (int i = 0; i < argc; i++) {
//        printf ("[%s]", * (argv + i) );
//    }
//    printf ("\n");
//    return "Hello";
//}

struct route_t *route (const char *pattern, char * (*handler) (const char *method, int argc, char **argv) ) {
    struct route_t *self = malloc (sizeof (struct route_t) );
    // struct data = malloc(sizeof (struct data));
    //

    /*************************************************************************
    * Now we are going to compile the regular expression pattern, and handle *
    * any errors that are detected.                                          *
    *************************************************************************/

    int errornumber;
    PCRE2_SIZE erroroffset;

    self->re = pcre2_compile (
                   (PCRE2_SPTR) pattern,  /* the pattern */
                   PCRE2_ZERO_TERMINATED, /* indicates pattern is zero-terminated */
                   0,                     /* default options */
                   &errornumber,          /* for error number */
                   &erroroffset,          /* for error offset */
                   NULL);                 /* use default compile context */

    if (self->re == NULL) {
        PCRE2_UCHAR buffer[256];

        pcre2_get_error_message (errornumber, buffer, sizeof (buffer) );
        printf ("PCRE2 compilation failed at offset %d: %s\n", (int) erroroffset, buffer);
        return NULL;
    }

    if (self != NULL) {
        self->pattern = pattern;
        // self->path = route;
        self->handleRequest = handler;
    }

    return self;
}
