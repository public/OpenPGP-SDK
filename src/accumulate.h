typedef struct ops_key_data ops_key_data_t;

typedef struct
    {
    int nkeys; // while we are constructing a key, this is the offset
    int nkeys_allocated;
    ops_key_data_t *keys;
    } ops_keyring_t;    

void ops_parse_and_accumulate(ops_keyring_t *keyring,ops_parse_options_t *opt);
