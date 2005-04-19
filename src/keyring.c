#include "keyring.h"
#include "keyring_local.h"
#include <stdlib.h>
#include <string.h>

#ifdef DMALLOC
# include <dmalloc.h>
#endif

ops_key_data_t *
ops_keyring_find_key_by_id(const ops_keyring_t *keyring,
			   const unsigned char keyid[OPS_KEY_ID_SIZE])
    {
    int n;

    for(n=0 ; n < keyring->nkeys ; ++n)
	if(!memcmp(keyring->keys[n].keyid,keyid,OPS_KEY_ID_SIZE))
	    return &keyring->keys[n];

    return NULL;
    }

void ops_key_data_free(ops_key_data_t *key)
    {
    int n;

    for(n=0 ; n < key->nuids ; ++n)
	ops_user_id_free(&key->uids[n]);
    free(key->uids);
    key->uids=NULL;

    for(n=0 ; n < key->npackets ; ++n)
	ops_packet_free(&key->packets[n]);
    free(key->packets);
    key->packets=NULL;

    ops_public_key_free(&key->pkey);
    }

void ops_keyring_free(ops_keyring_t *keyring)
    {
    int n;

    for(n=0 ; n < keyring->nkeys ; ++n)
	ops_key_data_free(&keyring->keys[n]);
    free(keyring->keys);
    keyring->keys=NULL;
    }
