/** \file
 */

#ifndef OPS_SIGNATURE_H
#define OPS_SIGNATURE_H

#include "packet.h"
#include "util.h"
#include "create.h"

typedef struct ops_create_signature ops_create_signature_t;

ops_create_signature_t *ops_create_signature_new(void);
void ops_create_signature_delete(ops_create_signature_t *sig);

ops_boolean_t
ops_check_certification_signature(const ops_public_key_t *key,
				  const ops_user_id_t *id,
				  const ops_signature_t *sig,
				  const ops_public_key_t *signer,
				  const unsigned char *raw_packet);
ops_boolean_t
ops_check_subkey_signature(const ops_public_key_t *key,
			   const ops_public_key_t *subkey,
			   const ops_signature_t *sig,
			   const ops_public_key_t *signer,
			   const unsigned char *raw_packet);
ops_boolean_t
ops_check_direct_signature(const ops_public_key_t *key,
			   const ops_signature_t *sig,
			   const ops_public_key_t *signer,
			   const unsigned char *raw_packet);
ops_boolean_t
ops_check_hash_signature(ops_hash_t *hash,
			 const ops_signature_t *sig,
			 const ops_public_key_t *signer);
void ops_signature_start_key_signature(ops_create_signature_t *sig,
				       const ops_public_key_t *key,
				       const ops_user_id_t *id,
				       ops_sig_type_t type);
void ops_signature_start_plaintext_signature(ops_create_signature_t *sig,
					     ops_secret_key_t *key,
					     ops_hash_algorithm_t hash,
					     ops_sig_type_t type);
void ops_signature_add_data(ops_create_signature_t *sig,const void *buf,
			    size_t length);
ops_hash_t *ops_signature_get_hash(ops_create_signature_t *sig);
void ops_signature_hashed_subpackets_end(ops_create_signature_t *sig);
void ops_write_signature(ops_create_signature_t *sig,ops_public_key_t *key,
			 ops_secret_key_t *skey,ops_create_info_t *opt);
void ops_signature_add_creation_time(ops_create_signature_t *sig,time_t when);
void ops_signature_add_issuer_key_id(ops_create_signature_t *sig,
				     const unsigned char keyid[OPS_KEY_ID_SIZE]);
void ops_signature_add_primary_user_id(ops_create_signature_t *sig,
				       ops_boolean_t primary);

#endif
