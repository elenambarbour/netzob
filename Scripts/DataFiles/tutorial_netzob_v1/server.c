/* Global includes */
#include <string.h>

/* Local includes */
#include "amo_net.h"
#include "amo_api.h"
#include "amo_parser.h"
#include "common.h"

int main() {
  int fd;
  unsigned char buffIN[BUFFLEN];
  unsigned char buffOUT[BUFFLEN];
  int sizeResponse = 0;

  /* Init */
  fd = net_listen();
  api_init();

  /* Main loop */
  printf("\nReady to read incomming messages\n");
  while(1) {
    /* Clean buffers */
    memset(buffIN, 0x0, BUFFLEN);
    memset(buffOUT, 0x0, BUFFLEN);

    net_read(fd, buffIN, BUFFLEN);
    printf("-> Read: %s\n", buffIN);

    if( (sizeResponse = parse_request_and_build_response( buffIN, buffOUT )) < 0)
      printf("[ERROR] main.c/main() Cannot handle request message.\n");
    else {
      net_send(fd, buffOUT, sizeResponse);
    }
    printf("\n");
  }
  
  net_close(fd);

  return 0;
}
