#include "packet.h"

typedef struct ops_key_data ops_key_data_t;

typedef struct
    {
    int nkeys; // while we are constructing a key, this is the offset
    int nkeys_allocated;
    ops_key_data_t *keys;
    } ops_keyring_t;    

ops_key_data_t *
ops_keyring_find_key_by_id(const ops_keyring_t *keyring,
			   const unsigned char keyid[OPS_KEY_ID_SIZE]);
