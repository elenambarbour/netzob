#ifndef AMO_NET_H
#define AMO_NET_H 

#define _BSD_SOURCE

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>


#define PORT 4242


/* net functions */

int net_listen();

int net_connect();

void net_close(int);

void net_send(int, unsigned char *, int);

void net_read(int, unsigned char *, int);

#endif
