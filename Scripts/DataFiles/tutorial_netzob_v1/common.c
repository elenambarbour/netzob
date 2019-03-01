#include "common.h"

void hexdump(unsigned char *buf, int dlen) {
  char c[OPL + 1];
  int i, ct;

  if (dlen < 0) {
    printf("WARNING: computed dlen %d\n", dlen);
    dlen = 0;
  }

  for (i = 0; i < dlen; ++i) {
    if (i == 0)
      printf("   DATA: ");
    else if ((i % OPL) == 0) {
      c[OPL] = '\0';
      printf("\t\"%s\"\n   DATA: ", c);
    }
    ct = buf[i] & 0xff;
    c[i % OPL] = (ct >= ' ' && ct <= '~') ? ct : '.';
    printf("%02x ", ct);
  }
  c[i % OPL] = '\0';
  for (; i % OPL; ++i)
    printf("   ");
  printf("\t\"%s\"\n", c);
}
