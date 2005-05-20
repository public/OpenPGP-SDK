/** \file
 */

#include "packet.h"
#include "util.h"
#include "create.h"

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
void ops_signature_start(ops_create_signature_t *sig,
			 const ops_public_key_t *key,
			 const ops_user_id_t *id);
void ops_signature_hashed_subpackets_end(ops_create_signature_t *sig);
void ops_signature_end(ops_create_signature_t *sig,ops_public_key_t *key,
		       ops_secret_key_t *skey);
void ops_signature_add_creation_time(ops_create_signature_t *sig,time_t when);
void ops_signature_add_issuer_key_id(ops_create_signature_t *sig,
				     const unsigned char keyid[OPS_KEY_ID_SIZE]);
void ops_signature_add_primary_user_id(ops_create_signature_t *sig,
				       ops_boolean_t primary);

