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
