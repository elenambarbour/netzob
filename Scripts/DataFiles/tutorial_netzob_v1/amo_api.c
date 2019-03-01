#include "amo_api.h"


unsigned char key = 0x42;

int api_init() {
  current_state = UNIDENTIFIED;
  return 0;
}


/* auth/unauth functions */

int api_identify(unsigned char *name) {
  unsigned char tmpName[10];

  strcpy(tmpName, name);

  if( strlen(tmpName) > 0) {
    current_state = IDENTIFIED;
    return 0;
  }
  else {
    current_state = UNIDENTIFIED;
    return -1;
  }
}

int api_authentify(unsigned char *password) {
  if( strlen(password) > 0) {
    current_state = AUTHENTIFIED;
    return 0;
  }
  else {
    current_state = UNIDENTIFIED;
    return -1;
  }
}

int api_bye() {
  current_state = UNIDENTIFIED;
  return 0;
}


/* system functions */

int api_stats(struct amo_stats *current_stats) {
  if( current_state == IDENTIFIED || current_state == AUTHENTIFIED ) {
    current_stats->counter = 32000;
    current_stats->len = 127;
    current_stats->max = 512;
    return 0;
  }
  else
    return -1;
}

int api_info(struct amo_info *current_info) {
  if( current_state == IDENTIFIED || current_state == AUTHENTIFIED ) {
    current_info->counter = 32000;
    current_info->len = 127;
    current_info->max = 512;
    return 0;
  }
  else
    return -1;
}


/* crypto functions */

int api_encrypt(unsigned char *in, unsigned int len, unsigned char *out) {
  unsigned int i;
  char tmpData[10];

  if( current_state == AUTHENTIFIED ) {
    strcpy(tmpData, in);
    for(i = 0; i < len; i++)
      tmpData[i] = (in[i] ^ key) % 0xff;
    strcpy(out, tmpData);
    return 0;
  }
  else
    return -1;
}

int api_decrypt(unsigned char *in, unsigned int len, unsigned char *out) {
  return api_encrypt(in, len, out);
}
