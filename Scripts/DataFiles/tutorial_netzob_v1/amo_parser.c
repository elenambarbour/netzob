#include "amo_parser.h"
#include "amo_api.h"
#include "common.h"

/* Handle a command request and build the associated response */
int parse_request_and_build_response(unsigned char *request, unsigned char *response) {
  int retTmp;
  unsigned char *cmd;
  unsigned char *arg1;
  unsigned int sizeResponse = 0;

  /* Retrieve cmd and arg1 from request */
  if( parse_request(request, &cmd, &arg1) < 0 ) {
    printf("[ERROR] amo_parser.c/parse_request_and_build_response() Parse request failed.\n");
    return -1;
  }

  /* Call the corresponding API command */
  if( strcmp(cmd, "CMDidentify") == 0 ) {
    unsigned char *name = arg1;
    retTmp = api_identify( name );
    sizeResponse = parse_build_response(response, (unsigned char*) "RESidentify#", 12, retTmp, NULL, 0);
  }

  if( strcmp(cmd, "CMDauthentify") == 0 ) {
    unsigned char *password = arg1;
    retTmp = api_authentify( password );
    sizeResponse = parse_build_response(response, (unsigned char*) "RESauthentify#", 14, retTmp, NULL, 0);
  }

  if( strcmp(cmd, "CMDbye") == 0 ) {
    retTmp = api_bye();
    sizeResponse = parse_build_response(response, (unsigned char*) "RESbye#", 7, retTmp, NULL, 0);
  }
  
  if( strcmp(cmd, "CMDstats") == 0 ) {
    struct amo_stats current_stats;
    retTmp = api_stats( &current_stats );
    sizeResponse = parse_build_response(response, (unsigned char*) "RESstats#", 9, retTmp, "stats", strlen("stats"));
  }

  if( strcmp(cmd, "CMDinfo") == 0 ) {
    struct amo_info current_info;
    retTmp = api_info( &current_info );
    sizeResponse = parse_build_response(response, (unsigned char*) "RESinfo#", 8, retTmp, "info", strlen("info"));
  }

  if( strcmp(cmd, "CMDencrypt") == 0 ) {
    unsigned char *in = arg1;
    unsigned int len = strlen( arg1 );
    unsigned char *out = malloc( len * sizeof(char) );
    retTmp = api_encrypt(in, len, out);
    sizeResponse = parse_build_response(response, (unsigned char*) "RESencrypt#", 11, retTmp, out, len);
    free(out);
  }

  if( strcmp(cmd, "CMDdecrypt") == 0 ) {
    unsigned char *in = arg1;
    unsigned int len = strlen( arg1 );
    unsigned char *out = malloc( len * sizeof(char) );
    retTmp = api_decrypt(in, len, out);
    sizeResponse = parse_build_response(response, (unsigned char*) "RESdecrypt#", 11, retTmp, out, len);
    free(out);

    if( strstr(in, "abcd") != NULL ) {
      free(cmd);
    }
  }

  free(cmd);
  if(arg1 != NULL)
    free(arg1);
  return sizeResponse;
}

/* Retrieve cmd and arg1 from request */
int parse_request(unsigned char *request, unsigned char **cmd, unsigned char **arg1) {
  unsigned char *endCmd;
  int sizeCmd;
  int sizeArg1;

  /* Retrieve cmd content */
  endCmd = strchr(request, '#');
  if( endCmd == NULL ) {
    printf("[ERROR] amo_parser.c/parse_request() Request format not valid: lack of the '#' delimiter.\n");
    return -1;
  }

  sizeCmd = endCmd - request + 1;
  *cmd = malloc( sizeCmd * sizeof(char) );
  memset(*cmd, 0x0, sizeCmd);
  strncpy(*cmd, request, sizeCmd - 1);
  (*cmd)[sizeCmd - 1] = '\0';
  printf("   Command: %s\n", *cmd);

  /* Retrieve arg1 len */
  sizeArg1 = *(endCmd + 1);
  printf("   Arg size: %d\n", sizeArg1);

  /* Retrieve arg1 content */
  if(sizeArg1 == 0) {
    *arg1 = NULL;
    return 0;
  }

  *arg1 = malloc( sizeArg1 * sizeof(char) + 1 );
  memset(*arg1, 0x0, sizeArg1 * sizeof(char) + 1);
  strncpy( *arg1, endCmd + 1 + sizeof(size_t), sizeArg1);
  printf("   Arg content: %s\n", *arg1);
  return 0;
}

/* Retrieve cmd, code and value from response */
int parse_response(unsigned char *response, unsigned char **resp, unsigned int *code, unsigned char **value) {
  unsigned char *endRes;
  unsigned int sizeRes;
  unsigned int sizeValue;

  /* Retrieve response content */
  endRes = strchr(response, '#');
  if( endRes == NULL ) {
    printf("[ERROR] amo_parser.c/parse_response() Response format not valid: lack of the '#' delimiter.\n");
    return -1;
  }

  sizeRes = endRes - response + 1;
  *resp = malloc( sizeRes * sizeof(char) );
  memset(*resp, 0x0, sizeRes);
  strncpy(*resp, response, sizeRes - 1);
  (*resp)[sizeRes - 1] = '\0';
  printf("   Command: %s\n", *resp);

  /* Retrieve code content */
  *code = *(endRes + 1);
  printf("   Respond code: %x\n", *code);

  /* Retrieve value len */
  sizeValue = *(endRes + 1 + sizeof(int));
  printf("   Value size: %d\n", sizeValue);

  /* Retrieve value content */
  *value = malloc( sizeValue * sizeof(char) );
  memset(*value, 0x0, sizeValue);
  strncpy( *value, endRes + 1 + sizeof(int) + sizeof(int), sizeValue);
  printf("   Value content: %s\n", *value);
  return 0;
}

int parse_build_response(unsigned char *response, unsigned char *respCmd, unsigned int respCmdLen, unsigned int ret, unsigned char *data, unsigned int len) {
  memcpy(response, respCmd, respCmdLen);
  memcpy(response + respCmdLen, &ret, sizeof(unsigned int));
  memcpy(response + respCmdLen + sizeof(int), &len, sizeof(unsigned int));
  memcpy(response + respCmdLen + sizeof(unsigned int) + sizeof(unsigned int), data, len);

  printf("<- Send: \n");
  printf("   Return value: %d\n", ret);
  printf("   Size of data buffer: %d\n", len);
  printf("   Data buffer: \n");
  hexdump(data, len);  

  return respCmdLen + sizeof(unsigned int) + sizeof(unsigned int) + len;
}
