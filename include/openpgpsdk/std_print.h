/** \file
 */

#ifndef OPS_STD_PRINT_H
#define OPS_STD_PRINT_H

#include "openpgpsdk/packet.h"
#include "openpgpsdk/packet-parse.h"
#include "openpgpsdk/keyring.h"

void ops_print_pk_session_key(ops_content_tag_t tag,
                          const ops_pk_session_key_t *key);
void ops_print_public_key(const ops_key_data_t *key);

void ops_print_public_key_verbose(const ops_key_data_t *key);

void ops_print_secret_key(const ops_key_data_t *key);
void ops_print_secret_key_verbose(const ops_key_data_t *key);

int ops_print_packet(const ops_parser_content_t *content_);
#endif
