#ifndef AMO_PARSER_H
#define AMO_PARSER_H 

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* parse functions */

int parse_request_and_build_response(unsigned char *, unsigned char *);

int parse_request(unsigned char *, unsigned char **, unsigned char **);

int parse_response(unsigned char *, unsigned char **, unsigned int *, unsigned char **);

int parse_build_response(unsigned char *, unsigned char*, unsigned int, unsigned int, unsigned char *, unsigned int);

#endif
