/** \file
 */

#ifndef OPS_STD_PRINT_H
#define OPS_STD_PRINT_H

#include "openpgpsdk/packet.h"
#include "openpgpsdk/packet-parse.h"
#include "openpgpsdk/keyring.h"

void print_bn( const char *name, 
		      const BIGNUM *bn);
void ops_print_pk_session_key(ops_content_tag_t tag,
                          const ops_pk_session_key_t *key);
void ops_print_public_keydata(const ops_keydata_t *key);

void ops_print_public_keydata_verbose(const ops_keydata_t *key);
void ops_print_public_key(const ops_public_key_t *pkey);

void ops_print_secret_keydata(const ops_keydata_t *key);
void ops_print_secret_keydata_verbose(const ops_keydata_t *key);
//void ops_print_secret_key(const ops_content_tag_t type, const ops_secret_key_t* skey);
int ops_print_packet(const ops_parser_content_t *content_);
#endif
