#include "keyring.h"
#include "keyring_local.h"

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
