/** \file packet-decode.h
 * packet decode related headers.
 *
 * $Id$
 */

#ifndef OPS_PACKET_DECODE_H
#define OPS_PACKET_DECODE_H

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
    } decoded_t;


typedef struct
    {
    unsigned char mask;
    char * string;
    } bit_map_t;

void decoded_init(decoded_t * decoded);
void decoded_free(decoded_t * decoded);

decoded_t * decode_ss_preferred_compression(ops_ss_preferred_compression_t ss_preferred_compression);
char * decode_single_ss_preferred_compression(unsigned char octet);

decoded_t * decode_ss_preferred_hash(ops_ss_preferred_hash_t ss_preferred_hash);
char * decode_single_ss_preferred_hash(unsigned char octet);

decoded_t * decode_ss_preferred_ska(ops_ss_preferred_ska_t ss_preferred_ska);
char * decode_single_ss_preferred_ska(unsigned char octet);

decoded_t * decode_ss_features(ops_ss_features_t ss_features);
char * decode_single_ss_feature(unsigned char octet, bit_map_t *map);

decoded_t *decode_ss_key_flags(ops_ss_key_flags_t ss_key_flags);
char *decode_single_ss_key_flag(unsigned char octet, bit_map_t *map);

decoded_t *decode_ss_key_server_prefs(ops_ss_key_server_prefs_t ss_key_server_prefs);
char *decode_single_ss_key_server_prefs(unsigned char octet, bit_map_t *map);

/* vim:set textwidth=120: */
/* vim:set ts=8: */

#endif /* OPS_PACKET_DECODE_H */
