/** \file 
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
    } ops_text_t;


typedef struct
    {
    unsigned char mask;
    char * string;
    } bit_map_t;

void ops_text_init(ops_text_t * text);
void ops_text_free(ops_text_t * text);

char *ops_str_from_single_packet_tag(unsigned char octet);
char *ops_str_from_single_signature_subpacket_type(unsigned char octet);

char *ops_str_from_single_signature_type(unsigned char octet);

char *ops_str_from_single_pka(unsigned char octet);

ops_text_t *ops_text_from_ss_preferred_compression(ops_ss_preferred_compression_t ss_preferred_compression);
char *ops_str_from_single_ss_preferred_compression(unsigned char octet);

ops_text_t *ops_text_from_ss_preferred_hash(ops_ss_preferred_hash_t ss_preferred_hash);
char *ops_str_from_single_hash_algorithm(unsigned char octet);

ops_text_t *ops_text_from_ss_preferred_ska(ops_ss_preferred_ska_t ss_preferred_ska);
char *ops_str_from_single_ss_preferred_ska(unsigned char octet);

char *ops_str_from_ss_revocation_reason_code(unsigned char octet);

ops_text_t *ops_text_from_ss_features(ops_ss_features_t ss_features);
char *ops_str_from_single_ss_feature(unsigned char octet, bit_map_t *map);

ops_text_t *ops_text_from_ss_key_flags(ops_ss_key_flags_t ss_key_flags);
char *ops_str_from_single_ss_key_flag(unsigned char octet, bit_map_t *map);

ops_text_t *ops_text_from_ss_key_server_prefs(ops_ss_key_server_prefs_t ss_key_server_prefs);
char *ops_str_from_single_ss_key_server_prefs(unsigned char octet, bit_map_t *map);

ops_text_t *ops_text_from_ss_notation_data_flags(ops_ss_notation_data_t ss_notation_data);

/* vim:set textwidth=120: */
/* vim:set ts=8: */

#endif /* OPS_PACKET_TO_TEXT_H */
