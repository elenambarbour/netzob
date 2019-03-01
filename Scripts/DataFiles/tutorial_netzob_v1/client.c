/* Global includes */
#include <string.h>

/* Local includes */
#include "amo_net.h"
#include "amo_parser.h"
#include "common.h"

int do_command(int fd, unsigned char *request, unsigned char *arg) {
  unsigned char buff[BUFFLEN];
  int code;
  unsigned char *response;
  unsigned char *value = NULL;
  size_t sizeArg;

  /* Clean buffer */
  memset(buff, 0x0, BUFFLEN);
  
  /* Build and send request */
  strcpy((char *) buff, (char *) request);
  sizeArg = strlen(arg);
  memcpy(buff + strlen(request), &sizeArg, sizeof(size_t));
  strcpy((char *) (buff + strlen(request) + sizeof(size_t)), (char *) arg);
  printf("-> Send: %s\n", buff);
  net_send(fd, buff, strlen(request) + sizeof(size_t) + strlen(arg));
  hexdump(buff, strlen(request) + sizeof(size_t) + strlen(arg));

  /* Receive response */
  memset(buff, 0x0, BUFFLEN);
  net_read(fd, buff, BUFFLEN);
  printf("<- Read: \n");

  /* Retrieve code and value from request */
  if( parse_response(buff, &response, &code, &value) < 0 ) {
    printf("[ERROR] client.c/do_command() Parse request failed.\n");
    return -1;
  }

  printf("\n");
  if(value != NULL)
    free(value);

  return 0;
}

void test1(int fd) {
  /* identify */
  do_command(fd, (unsigned char*) "CMDidentify#", "fred");

  /* get info */
  do_command(fd, (unsigned char*) "CMDinfo#", "");

  /* get stats */
  do_command(fd, (unsigned char*) "CMDstats#", "");

  /* authentify */
  do_command(fd, (unsigned char*) "CMDauthentify#", "myPasswd!");

  /* encrypt */
  do_command(fd, (unsigned char*) "CMDencrypt#", "123456test");

  /* decrypt */
  do_command(fd, (unsigned char*) "CMDdecrypt#", "spqvwt6'16");

  /* decrypt */
  do_command(fd, (unsigned char*) "CMDbye#", "");
}

void test2(int fd) {
  /* encrypt */
  do_command(fd, (unsigned char*) "CMDencrypt#", "123456test");

  /* decrypt */
  do_command(fd, (unsigned char*) "CMDdecrypt#", "spqvwt6'16");
}

void test3(int fd) {
  /* encrypt */
  do_command(fd, (unsigned char*) "CMDencrypt#", "123456test");

  /* decrypt */
  do_command(fd, (unsigned char*) "CMDdecrypt#", "abcdwt6'16");
}

void test4(int fd) {
  /* identify */
  do_command(fd, (unsigned char*) "CMDidentify#", "Roberto");

  /* get info */
  do_command(fd, (unsigned char*) "CMDinfo#", "");

  /* get stats */
  do_command(fd, (unsigned char*) "CMDstats#", "");

  /* authentify */
  do_command(fd, (unsigned char*) "CMDauthentify#", "aStrongPwd");

  /* encrypt */
  do_command(fd, (unsigned char*) "CMDencrypt#", "abcdef");

  /* decrypt */
  do_command(fd, (unsigned char*) "CMDdecrypt#", "# !&'$");

  /* decrypt */
  do_command(fd, (unsigned char*) "CMDbye#", "");
}

void test5(int fd) {
  /* identify */
  do_command(fd, (unsigned char*) "CMDidentify#", "Roberto");

  /* get info */
  do_command(fd, (unsigned char*) "CMDinfo#", "");

  /* get stats */
  do_command(fd, (unsigned char*) "CMDstats#", "");

  /* authentify */
  do_command(fd, (unsigned char*) "CMDauthentify#", "aStrongPwd");

  /* decrypt */
  do_command(fd, (unsigned char*) "CMDdecrypt#", "# !&'$");

  /* decrypt */
  do_command(fd, (unsigned char*) "CMDbye#", "");
}

int main() {
  int fd;

  /* Init */
  fd = net_connect();

  /* 1st session */
  /* test1(fd); */

  /* 2nd session */
  test5(fd);

  net_close(fd);

  return 0;
}
