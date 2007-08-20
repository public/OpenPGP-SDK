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
void create_testfile(const char *name);
#define MAXBUF 1024

ops_parse_cb_return_t
callback_general(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);
ops_parse_cb_return_t
callback_cmd_get_secret_key(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);
ops_parse_cb_return_t
callback_cmd_get_secret_key_passphrase(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);
ops_parse_cb_return_t
callback_literal_data(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);

void reset_vars();
int file_compare(char* file1, char* file2);

ops_keyring_t pub_keyring;
ops_keyring_t sec_keyring;
unsigned char* literal_data;
size_t sz_literal_data;
char* alpha_user_id;
#endif

