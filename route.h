#ifndef __ROUTE_H__
#define __ROUTE_H__

#define PCRE2_CODE_UNIT_WIDTH 8

#include <stdio.h>
#include <string.h>
#include <pcre2.h>
#include <stdbool.h>
#include <microhttpd.h>


struct route_t {
    const char *pattern;
    pcre2_code *re;
    enum MHD_Result (* route) (struct MHD_Connection *connection, const char *url, const char *method);
    bool (* match) (const char *pattern);
    char * (* handleRequest) (const char *method, int argc, char **argv);
};

//struct route_t* route (const char *pattern, enum MHD_Result (* function) (struct MHD_Connection *connection,
//                       const char *url, const char *method) );

struct route_t *route (const char *pattern, char * (*handler) (const char *method, int argc, char **argv) );

#endif