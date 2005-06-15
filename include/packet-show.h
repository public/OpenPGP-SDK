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
    char **strings;
    } list_t;

typedef struct
    {
    list_t known;
    list_t unknown;
    } ops_text_t;


typedef struct
    {
    unsigned char mask;
    char *string;
    } bit_map_t;

void ops_text_init(ops_text_t *text);
void ops_text_free(ops_text_t *text);

char *ops_show_packet_tag(ops_packet_tag_t packet_tag);
char *ops_show_ss_type(ops_ss_type_t ss_type);

char *ops_show_sig_type(ops_sig_type_t sig_type);
char *ops_show_pka(ops_public_key_algorithm_t pka);

ops_text_t *ops_showall_ss_preferred_compression(ops_ss_preferred_compression_t ss_preferred_compression);
char *ops_show_ss_preferred_compression(unsigned char octet);

ops_text_t *ops_showall_ss_preferred_hash(ops_ss_preferred_hash_t ss_preferred_hash);
char *ops_show_hash_algorithm(unsigned char octet);

ops_text_t *ops_showall_ss_preferred_ska(ops_ss_preferred_ska_t ss_preferred_ska);
char *ops_show_ss_preferred_ska(unsigned char octet);

char *ops_show_ss_rr_code(ops_ss_rr_code_t ss_rr_code);

ops_text_t *ops_showall_ss_features(ops_ss_features_t ss_features);
char *ops_show_ss_feature(unsigned char octet, bit_map_t *map);

ops_text_t *ops_showall_ss_key_flags(ops_ss_key_flags_t ss_key_flags);
char *ops_show_ss_key_flag(unsigned char octet, bit_map_t *map);

ops_text_t *ops_showall_ss_key_server_prefs(ops_ss_key_server_prefs_t ss_key_server_prefs);
char *ops_show_ss_key_server_prefs(unsigned char octet, bit_map_t *map);

ops_text_t *ops_showall_ss_notation_data_flags(ops_ss_notation_data_t ss_notation_data);

/* vim:set textwidth=120: */
/* vim:set ts=8: */

#endif /* OPS_PACKET_TO_TEXT_H */
