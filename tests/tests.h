#ifndef __TESTS__
#define __TESTS_

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openpgpsdk/memory.h>
#include <openpgpsdk/create.h>

int mktmpdir();
extern char dir[];
void create_testtext(const char *text, char *buf, const int maxlen);
void create_testdata(const char *text, unsigned char *buf, const int maxlen);
#define MAXBUF 128

ops_parse_cb_return_t
callback_general(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);
ops_parse_cb_return_t
callback_cmd_get_secret_key(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);
ops_parse_cb_return_t
callback_cmd_get_secret_key_passphrase(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);

ops_keyring_t pub_keyring;
ops_keyring_t sec_keyring;
#endif

