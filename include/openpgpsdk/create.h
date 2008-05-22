/** \file
 */

#ifndef OPS_CREATE_H
#define OPS_CREATE_H

#include "types.h"
#include "packet.h"
#include "crypto.h"
#include "memory.h"
#include "errors.h"
#include "keyring.h"

typedef struct ops_writer_info ops_writer_info_t;
/**
 * \ingroup Create
 * the writer function prototype
 */
typedef ops_boolean_t ops_writer_t(const unsigned char *src,
				      unsigned length,
				      ops_error_t **errors,
				      ops_writer_info_t *winfo);
typedef ops_boolean_t ops_writer_finaliser_t(ops_error_t **errors,
					     ops_writer_info_t *winfo);
typedef void ops_writer_destroyer_t(ops_writer_info_t *winfo);

ops_create_info_t *ops_create_info_new(void);
void ops_create_info_delete(ops_create_info_t *info);
void *ops_writer_get_arg(ops_writer_info_t *winfo);
ops_boolean_t ops_stacked_write(const void *src,unsigned length,
				ops_error_t **errors,
				ops_writer_info_t *winfo);

void ops_writer_set(ops_create_info_t *info,
		    ops_writer_t *writer,
		    ops_writer_finaliser_t *finaliser,
		    ops_writer_destroyer_t *destroyer,
		    void *arg);
void ops_writer_push(ops_create_info_t *info,
		     ops_writer_t *writer,
		     ops_writer_finaliser_t *finaliser,
		     ops_writer_destroyer_t *destroyer,
		     void *arg);
void ops_writer_pop(ops_create_info_t *info);
void ops_writer_generic_destroyer(ops_writer_info_t *winfo);
ops_boolean_t ops_writer_passthrough(const unsigned char *src,
				     unsigned length,
				     ops_error_t **errors,
				     ops_writer_info_t *winfo);

void ops_writer_set_fd(ops_create_info_t *info,int fd);
ops_boolean_t ops_writer_close(ops_create_info_t *info);

ops_boolean_t ops_write(const void *src,unsigned length,
			ops_create_info_t *opt);
ops_boolean_t ops_write_length(unsigned length,ops_create_info_t *opt);
ops_boolean_t ops_write_ptag(ops_content_tag_t tag,ops_create_info_t *opt);
ops_boolean_t ops_write_scalar(unsigned n,unsigned length,
			       ops_create_info_t *opt);
ops_boolean_t ops_write_mpi(const BIGNUM *bn,ops_create_info_t *opt);
ops_boolean_t ops_write_encrypted_mpi(const BIGNUM *bn, ops_crypt_t* crypt, ops_create_info_t *info);
ops_boolean_t ops_write_ss_header(unsigned length,ops_content_tag_t type,
				  ops_create_info_t *opt);

void ops_fast_create_rsa_public_key(ops_public_key_t *key,time_t time,
				    BIGNUM *n,BIGNUM *e);
void ops_create_rsa_public_key(ops_public_key_t *key,time_t time,
			       const BIGNUM *n,const BIGNUM *e);
void ops_build_public_key(ops_memory_t *out,const ops_public_key_t *key,
			  ops_boolean_t make_packet);
ops_boolean_t ops_write_struct_public_key(const ops_public_key_t *key,
					  ops_create_info_t *opt);
ops_boolean_t ops_write_rsa_public_key(time_t time,const BIGNUM *n,
				       const BIGNUM *e,
				       ops_create_info_t *opt);

void ops_fast_create_user_id(ops_user_id_t *id,unsigned char *user_id);
ops_boolean_t ops_write_struct_user_id(ops_user_id_t *id,
				       ops_create_info_t *opt);
ops_boolean_t ops_write_user_id(const unsigned char *user_id,ops_create_info_t *opt);

void ops_create_rsa_secret_key(ops_secret_key_t *key,const BIGNUM *p,
			       const BIGNUM *q,const BIGNUM *d,
			       const BIGNUM *u,const BIGNUM *n,
			       const BIGNUM *e);
void ops_fast_create_rsa_secret_key(ops_secret_key_t *key,time_t time,
				    BIGNUM *p,BIGNUM *q,BIGNUM *d,BIGNUM *u,
				    BIGNUM *n,BIGNUM *e);
ops_boolean_t ops_write_struct_secret_key(const ops_secret_key_t *key,
                                          const unsigned char* passphrase,
                                          const size_t pplen,
					  ops_create_info_t *info);

ops_pk_session_key_t *ops_create_pk_session_key(const ops_keydata_t *key);

void ops_create_m_buf(ops_pk_session_key_t *session_key, unsigned char *buf);

// RENAMED from ops_boolean_t ops_write_literal_data(const unsigned char *data, 
ops_boolean_t ops_write_literal_data_from_buf(const unsigned char *data, 
                                     const int maxlen, 
                                     const ops_literal_data_type_t type,
                                     ops_create_info_t *info);
ops_boolean_t ops_write_literal_data_from_file(const char *filename, 
                                               const ops_literal_data_type_t type,
                                               ops_create_info_t *info);

ops_memory_t* ops_write_buf_from_file(const char *filename);
int ops_write_file_from_buf(const char* filename, const char* buf, const size_t len);

ops_boolean_t ops_write_symmetrically_encrypted_data(const unsigned char *data, 
                                                     const int len, 
                                                     ops_create_info_t *info);

ops_boolean_t ops_write_se_ip_data(const unsigned char *data,
                                   const unsigned int len,
                                   ops_crypt_t *crypt,
                                   ops_create_info_t *info);
ops_boolean_t ops_write_pk_session_key(ops_create_info_t *info,
				       ops_pk_session_key_t *pksk);
ops_boolean_t ops_calc_session_key_checksum(ops_pk_session_key_t *session_key, unsigned char *cs);
void ops_calc_mdc_hash(const unsigned char* preamble, const size_t sz_preamble, const unsigned char* data, const unsigned int len, unsigned char *hashed);

ops_boolean_t ops_write_one_pass_sig(const ops_secret_key_t* skey, const ops_hash_algorithm_t hash_alg, const ops_sig_type_t sig_type, ops_create_info_t* info);

ops_boolean_t ops_write_transferable_public_key(const ops_keydata_t *key, ops_boolean_t armoured, ops_create_info_t *info);
ops_boolean_t ops_write_transferable_secret_key(const ops_keydata_t *key, const unsigned char* passphrase, size_t pplen, ops_boolean_t armoured, ops_create_info_t *info);

#endif
