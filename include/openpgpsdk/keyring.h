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

const ops_key_data_t *
ops_keyring_find_key_by_id(const ops_keyring_t *keyring,
			   const unsigned char keyid[OPS_KEY_ID_SIZE]);
const ops_key_data_t *
ops_keyring_find_key_by_userid(const ops_keyring_t *keyring,
			       const char* userid);
void ops_key_data_free(ops_key_data_t *key);
void ops_keyring_free(ops_keyring_t *keyring);
void ops_dump_keyring(const ops_keyring_t *keyring);
const ops_public_key_t *
ops_get_public_key_from_data(const ops_key_data_t *data);
ops_boolean_t ops_key_is_secret(const ops_key_data_t *data);
const ops_secret_key_t *
ops_get_secret_key_from_data(const ops_key_data_t *data);
ops_secret_key_t *ops_decrypt_secret_key_from_data(const ops_key_data_t *key,
						   const char *pphrase);

void ops_keyring_read(ops_keyring_t *keyring,const char *file);

char *ops_malloc_passphrase(char *passphrase);
char *ops_get_passphrase(void);

void ops_keyring_list(const ops_keyring_t* keyring, const char* match);

void ops_set_secret_key(ops_parser_content_union_t* content,const ops_key_data_t *key);

const unsigned char* ops_get_key_id(const ops_key_data_t *key);

#endif
