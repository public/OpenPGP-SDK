/** \file
 */

#ifndef OPS_KEYRING_H
#define OPS_KEYRING_H

#include "packet.h"

typedef struct ops_key_data ops_key_data_t;

/** \struct ops_keyring_t
 * A keyring
 */

typedef struct
    {
    int nkeys; // while we are constructing a key, this is the offset
    int nkeys_allocated;
    ops_key_data_t *keys;
    } ops_keyring_t;    

ops_key_data_t *
ops_keyring_find_key_by_id(const ops_keyring_t *keyring,
			   const unsigned char keyid[OPS_KEY_ID_SIZE]);
void ops_key_data_free(ops_key_data_t *key);
void ops_keyring_free(ops_keyring_t *keyring);
void ops_dump_keyring(const ops_keyring_t *keyring);
const ops_public_key_t *
ops_get_public_key_from_data(const ops_key_data_t *data);

#endif
