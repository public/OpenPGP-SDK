typedef struct
    {
    unsigned int valid_count;
    ops_keydata_t * valid_keys;
    unsigned int invalid_count;
    ops_keydata_t * invalid_keys;
    unsigned int unknown_signer_count;
    unsigned char * unknown_keys;
    } ops_validate_result_t;

void ops_validate_result_free(ops_validate_result_t *result);

void ops_validate_key_signatures(ops_validate_result_t *result,
                                 const ops_keydata_t* keydata,
                                 const ops_keyring_t *ring,
                                 ops_parse_cb_return_t cb (const ops_parser_content_t *, ops_parse_cb_info_t *));
void ops_validate_all_signatures(ops_validate_result_t *result,
                                 const ops_keyring_t *ring,
                                 ops_parse_cb_return_t (const ops_parser_content_t *, ops_parse_cb_info_t *));

void ops_keydata_reader_set(ops_parse_info_t *pinfo,
			     const ops_keydata_t *key);

typedef struct
    {
    const ops_keydata_t *key;
    unsigned packet;
    unsigned offset;
    } validate_reader_arg_t;

typedef struct
    {
    ops_public_key_t pkey;
    ops_public_key_t subkey;
    ops_secret_key_t skey;
    enum
	{
	ATTRIBUTE=1,
	ID,
	} last_seen;
    ops_user_id_t user_id;
    ops_user_attribute_t user_attribute;
    unsigned char hash[OPS_MAX_HASH_SIZE];
    const ops_keyring_t *keyring;
    validate_reader_arg_t *rarg;
    ops_validate_result_t *result;
    ops_parse_cb_return_t (*cb_get_passphrase) (const ops_parser_content_t *, ops_parse_cb_info_t *);
    } validate_key_cb_arg_t;

typedef struct
    {
    enum
        {
        LITERAL_DATA,
        SIGNED_CLEARTEXT
        } use;
    union
        {
        ops_literal_data_body_t literal_data_body; 
        ops_signed_cleartext_body_t signed_cleartext_body; 
        } data;
    unsigned char hash[OPS_MAX_HASH_SIZE];
    const ops_keyring_t *keyring;
    validate_reader_arg_t *rarg;
    ops_validate_result_t *result;
    } validate_data_cb_arg_t;

ops_boolean_t ops_check_signature(const unsigned char *hash,
                                  unsigned length,
                                  const ops_signature_t *sig,
                                  const ops_public_key_t *signer);
ops_parse_cb_return_t
ops_validate_key_cb(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);

// EOF
