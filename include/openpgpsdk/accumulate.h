/** \file
 */

#ifndef OPS_ACCUMULATE_H
#define OPS_ACCUMULATE_H
#endif

#include "keyring.h"
#include "packet-parse.h"

int ops_parse_and_accumulate(ops_keyring_t *keyring,
			     ops_parse_info_t *parse_info);
