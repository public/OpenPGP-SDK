/** \file
 */

#ifndef OPS_STD_PRINT_H
#define OPS_STD_PRINT_H

void ops_print_public_key(const ops_key_data_t *key);

void ops_print_public_key_verbose(const ops_key_data_t *key);

void ops_print_secret_key(const ops_key_data_t *key);
void ops_print_secret_key_verbose(const ops_key_data_t *key);

int ops_print_packet(const ops_parser_content_t *content_);
#endif
