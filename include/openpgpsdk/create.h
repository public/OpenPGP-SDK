/** \file
 */

#ifndef OPS_CREATE_H
#define OPS_CREATE_H

#include "types.h"
#include "packet.h"
#include "crypto.h"
#include "memory.h"
#include "errors.h"

/** expected return values from the writer function
 */

enum ops_writer_ret_t
    {
    OPS_W_OK		=0,
    OPS_W_ERROR		=1,
    };

/**
 * \ingroup Create
 * the writer function prototype
 */
typedef ops_writer_ret_t ops_writer_t(const unsigned char *src,
				      unsigned length,
				      ops_writer_flags_t flags,
				      ops_error_t **errors,
				      void *arg);

typedef void ops_writer_destroyer_t(void *arg);

void ops_create_info_set_writer(ops_create_info_t *info,
				ops_writer_t *writer,
				ops_writer_destroyer_t *destroyer,
				void *arg);

ops_create_info_t *ops_create_info_new(void);
void ops_create_info_delete(ops_create_info_t *info);
void ops_create_info_set_writer_fd(ops_create_info_t *info,int fd);
void ops_create_info_close_writer(ops_create_info_t *info);

ops_boolean_t ops_write(const void *src,unsigned length,
			ops_create_info_t *opt);
ops_boolean_t ops_write_length(unsigned length,ops_create_info_t *opt);
ops_boolean_t ops_write_ptag(ops_content_tag_t tag,ops_create_info_t *opt);
ops_boolean_t ops_write_scalar(unsigned n,unsigned length,
			       ops_create_info_t *opt);
ops_boolean_t ops_write_mpi(const BIGNUM *bn,ops_create_info_t *opt);
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
					  ops_create_info_t *info);

#endif
