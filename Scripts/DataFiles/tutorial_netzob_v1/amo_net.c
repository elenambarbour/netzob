#include "amo_net.h"

struct sockaddr_in si_other;

int net_connect() {
  int sock;
  
  if ((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1) {
    perror("socket()");
    exit(1);
  }

  memset((char *) &si_other, 0, sizeof(si_other));
  si_other.sin_family = AF_INET;
  si_other.sin_port = htons(PORT);
  if (inet_aton("127.0.0.1", &si_other.sin_addr)==0) {
    fprintf(stderr, "inet_aton() failed\n");
    exit(1);
  }

  return sock;
}

int net_listen() {
  struct sockaddr_in si_me;
  int sock, n;
  
  if ((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1) {
    perror("socket()");
    exit(1);
  }

  n = 1;
  setsockopt( sock, SOL_SOCKET, SO_REUSEADDR,
	      (const char *) &n, sizeof( n ) );

  
  memset((char *) &si_me, 0, sizeof(si_me));
  si_me.sin_family = AF_INET;
  si_me.sin_port = htons(PORT);
  si_me.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(sock, (const struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
    perror("bind()");
    exit(1);
  }

  return sock;
}

void net_close(int sock) {
  close(sock);
}

void net_send(int sock, unsigned char *buf, int buflen) {
  int slen = sizeof(si_other);

  if (sendto(sock, buf, buflen, 0, (const struct sockaddr *)&si_other, slen) == -1) {
    perror("sendto()");
    exit(1);
  }
}

void net_read(int sock, unsigned char *buf, int buflen) {
  int slen = sizeof(si_other);

  if (recvfrom(sock, buf, buflen, 0, (struct sockaddr *)&si_other, &slen) == -1) {
    perror("recvfrom()");
    exit(1);
  }
}
