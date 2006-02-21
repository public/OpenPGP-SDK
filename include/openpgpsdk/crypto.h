/** \file
 */

#ifndef OPS_CRYPTO_H
#define OPS_CRYPTO_H

#include "util.h"
#include "packet.h"
#include "packet-parse.h"

#define OPS_MAX_HASH_SIZE	64
#define OPS_MIN_HASH_SIZE	16

typedef void ops_hash_init_t(ops_hash_t *hash);
typedef void ops_hash_add_t(ops_hash_t *hash,const unsigned char *data,
			unsigned length);
typedef unsigned ops_hash_finish_t(ops_hash_t *hash,unsigned char *out);

/** _ops_hash_t */
struct _ops_hash_t
    {
    ops_hash_algorithm_t algorithm;
    const char *name;
    ops_hash_init_t *init;
    ops_hash_add_t *add;
    ops_hash_finish_t *finish;
    void *data;
    };

typedef void ops_decrypt_set_iv_t(ops_decrypt_t *decrypt,
				  const unsigned char *iv);
typedef void ops_decrypt_set_key_t(ops_decrypt_t *decrypt,
				   const unsigned char *key);
typedef void ops_decrypt_init_t(ops_decrypt_t *decrypt);
typedef void ops_decrypt_resync_t(ops_decrypt_t *decrypt);
typedef size_t ops_decrypt_decrypt_t(ops_decrypt_t *decrypt,void *out,
				     const void *in,int count);
typedef void ops_decrypt_finish_t(ops_decrypt_t *decrypt);

struct _ops_decrypt_t
    {
    ops_symmetric_algorithm_t algorithm;
    size_t blocksize;
    size_t keysize;
    ops_decrypt_set_iv_t *set_iv; /* Call this before init! */
    ops_decrypt_set_iv_t *set_key; /* Call this before init! */
    ops_decrypt_init_t *init;
    ops_decrypt_resync_t *resync;
    ops_decrypt_decrypt_t *decrypt;
    ops_decrypt_finish_t *finish;
    unsigned char iv[OPS_MAX_BLOCK_SIZE];
    unsigned char civ[OPS_MAX_BLOCK_SIZE];
    unsigned char siv[OPS_MAX_BLOCK_SIZE]; /* Needed for weird v3 resync */
    unsigned char key[OPS_MAX_KEY_SIZE];
    int num;
    void *data;
    };

void ops_crypto_init(void);
void ops_crypto_finish(void);
void ops_hash_md5(ops_hash_t *hash);
void ops_hash_sha1(ops_hash_t *hash);
void ops_hash_any(ops_hash_t *hash,ops_hash_algorithm_t alg);
ops_hash_algorithm_t ops_hash_algorithm_from_text(const char *hash);
const char *ops_text_from_hash(ops_hash_t *hash);
unsigned ops_hash_size(ops_hash_algorithm_t alg);
unsigned ops_hash(unsigned char *out,ops_hash_algorithm_t alg,const void *in,
		  size_t length);

void ops_hash_add_int(ops_hash_t *hash,unsigned n,unsigned length);

ops_boolean_t ops_dsa_verify(const unsigned char *hash,size_t hash_length,
			     const ops_dsa_signature_t *sig,
			     const ops_dsa_public_key_t *dsa);
int ops_rsa_public_decrypt(unsigned char *out,const unsigned char *in,
			   size_t length,const ops_rsa_public_key_t *rsa);
int ops_rsa_private_encrypt(unsigned char *out,const unsigned char *in,
			    size_t length,const ops_rsa_secret_key_t *srsa,
			    const ops_rsa_public_key_t *rsa);

unsigned ops_block_size(ops_symmetric_algorithm_t alg);
unsigned ops_key_size(ops_symmetric_algorithm_t alg);

int ops_decrypt_data(ops_content_tag_t tag,ops_region_t *region,
		     ops_parse_info_t *parse_info);

void ops_decrypt_any(ops_decrypt_t *decrypt,ops_symmetric_algorithm_t alg);

void ops_reader_push_decrypt(ops_parse_info_t *pinfo,ops_decrypt_t *decrypt,
			     ops_region_t *region);
void ops_reader_pop_decrypt(ops_parse_info_t *pinfo);

// Hash everything that's read
void ops_reader_push_hash(ops_parse_info_t *pinfo,ops_hash_t *hash);
void ops_reader_pop_hash(ops_parse_info_t *pinfo);

#endif
