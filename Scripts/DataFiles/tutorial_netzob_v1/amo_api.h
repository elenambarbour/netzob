#ifndef AMO_API_H
#define AMO_API_H 

#include <string.h>

/* structures */

/* state machine */
enum api_state { UNIDENTIFIED, IDENTIFIED, AUTHENTIFIED} current_state;

/* stats */
struct amo_stats {
  short counter;
  short len;
  short max;
};

/* info */
struct amo_info {
  short counter;
  short len;
  short max;
};

int api_init();


/* auth/unauth functions */

int api_identify(unsigned char *);

int api_authentify(unsigned char *);

int api_bye();


/* system functions */

int api_stats(struct amo_stats*);

int api_info(struct amo_info*);


/* crypto functions */

int api_encrypt(unsigned char *, unsigned int, unsigned char *);

int api_decrypt(unsigned char *, unsigned int, unsigned char *);

#endif
