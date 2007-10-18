typedef struct
    {
    unsigned int valid_count;
    unsigned int invalid_count;
    unsigned int unknown_signer_count;
    } ops_validate_result_t;

void ops_validate_all_signatures(ops_validate_result_t *result,
				 const ops_keyring_t *ring);
void ops_key_data_reader_set(ops_parse_info_t *pinfo,
			     const ops_key_data_t *key);

typedef struct
    {
    const ops_key_data_t *key;
    unsigned packet;
    unsigned offset;
    } validate_reader_arg_t;

typedef struct
    {
    ops_public_key_t pkey;
    ops_public_key_t subkey;
    enum
	{
	ATTRIBUTE,
	ID
	} last_seen;
    ops_user_id_t user_id;
    ops_user_attribute_t user_attribute;
    const ops_keyring_t *keyring;
    validate_reader_arg_t *rarg;
    ops_validate_result_t *result;
    } validate_cb_arg_t;

// EOF
