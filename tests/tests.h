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

// test suites

#include "CUnit/Basic.h"

CU_pSuite suite_crypto();
extern CU_pSuite suite_packet_types();
extern CU_pSuite suite_rsa_decrypt();
extern CU_pSuite suite_rsa_encrypt();
extern CU_pSuite suite_rsa_signature();
extern CU_pSuite suite_rsa_verify();

// utility functions

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
ops_parse_cb_return_t
callback_pk_session_key(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);
ops_parse_cb_return_t
callback_signature(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);

void reset_vars();
int file_compare(char* file1, char* file2);

ops_keyring_t pub_keyring;
ops_keyring_t sec_keyring;
unsigned char* literal_data;
size_t sz_literal_data;
char* alpha_user_id;
char* bravo_user_id;
char* alpha_name;
char* bravo_name;
const ops_public_key_t *alpha_pkey;
const ops_secret_key_t *alpha_skey;
const ops_public_key_t *bravo_pkey;
const ops_secret_key_t *bravo_skey;
const ops_key_data_t *decrypter;
#endif

