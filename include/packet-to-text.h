/** \file packet-to_text.h
 *
 * $Id$
 */

#ifndef OPS_PACKET_TO_TEXT_H
#define OPS_PACKET_TO_TEXT_H

#ifndef OPS_PACKET_H
#include "packet.h"
#endif

typedef struct
    {
    unsigned int size;/* num of array slots allocated */
    unsigned int used; /* num of array slots currently used */
    char ** strings;
    } list_t;

typedef struct
    {
    list_t known;
    list_t unknown;
    } text_t;


typedef struct
    {
    unsigned char mask;
    char * string;
    } bit_map_t;

void text_init(text_t * text);
void text_free(text_t * text);

text_t * text_ss_preferred_compression(ops_ss_preferred_compression_t ss_preferred_compression);
char * text_single_ss_preferred_compression(unsigned char octet);

text_t * text_ss_preferred_hash(ops_ss_preferred_hash_t ss_preferred_hash);
char * text_single_ss_preferred_hash(unsigned char octet);

text_t * text_ss_preferred_ska(ops_ss_preferred_ska_t ss_preferred_ska);
char * text_single_ss_preferred_ska(unsigned char octet);

char *text_ss_revocation_reason_code(unsigned char octet);

text_t * text_ss_features(ops_ss_features_t ss_features);
char * text_single_ss_feature(unsigned char octet, bit_map_t *map);

text_t *text_ss_key_flags(ops_ss_key_flags_t ss_key_flags);
char *text_single_ss_key_flag(unsigned char octet, bit_map_t *map);

text_t *text_ss_key_server_prefs(ops_ss_key_server_prefs_t ss_key_server_prefs);
char *text_single_ss_key_server_prefs(unsigned char octet, bit_map_t *map);

text_t *text_ss_notation_data_flags(ops_ss_notation_data_t ss_notation_data);

/* vim:set textwidth=120: */
/* vim:set ts=8: */

#endif /* OPS_PACKET_TO_TEXT_H */
