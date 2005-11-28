/** \file
 */

#include <openpgpsdk/packet.h>
#include <openpgpsdk/crypto.h>
#include <openpgpsdk/create.h>
#include <assert.h>
#include <string.h>

#include <openpgpsdk/configure.h>
#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#endif

/**
 * \ingroup Utils
 *
 * Calculate a public key fingerprint.
 *
 * \param fp Where to put the calculated fingerprint
 * \param key The key for which the fingerprint is calculated
 */

void ops_fingerprint(ops_fingerprint_t *fp,const ops_public_key_t *key)
    {
    if(key->version == 2 || key->version == 3)
	{
	unsigned char *bn;
	int n;
	ops_hash_t md5;

	assert(key->algorithm == OPS_PKA_RSA
	       || key->algorithm == OPS_PKA_RSA_ENCRYPT_ONLY
	       || key->algorithm == OPS_PKA_RSA_SIGN_ONLY );

	ops_hash_md5(&md5);
	md5.init(&md5);

	n=BN_num_bytes(key->key.rsa.n);
	bn=alloca(n);
	BN_bn2bin(key->key.rsa.n,bn);
	md5.add(&md5,bn,n);

	n=BN_num_bytes(key->key.rsa.e);
	bn=alloca(n);
	BN_bn2bin(key->key.rsa.e,bn);
	md5.add(&md5,bn,n);

	md5.finish(&md5,fp->fingerprint);
	fp->length=16;
	}
    else
	{
	ops_memory_t mem;
	ops_hash_t sha1;

	memset(&mem,'\0',sizeof mem);

	ops_build_public_key(&mem,key,ops_false);

	ops_hash_sha1(&sha1);
	sha1.init(&sha1);

	ops_hash_add_int(&sha1,0x99,1);
	ops_hash_add_int(&sha1,mem.length,2);
	sha1.add(&sha1,mem.buf,mem.length);
	sha1.finish(&sha1,fp->fingerprint);
	fp->length=20;

	ops_memory_release(&mem);
	}
    }

/**
 * \ingroup Utils
 *
 * Calculate the Key ID from the public key.
 *
 * \param keyid Space for the calculated ID to be stored
 * \param key The key for which the ID is calculated
 */

void ops_keyid(unsigned char keyid[8],const ops_public_key_t *key)
    {
    if(key->version == 2 || key->version == 3)
	{
	unsigned char bn[8192];
	unsigned n=BN_num_bytes(key->key.rsa.n);

	assert(n <= sizeof bn);
	assert(key->algorithm == OPS_PKA_RSA
	       || key->algorithm == OPS_PKA_RSA_ENCRYPT_ONLY
	       || key->algorithm == OPS_PKA_RSA_SIGN_ONLY );
	BN_bn2bin(key->key.rsa.n,bn);
	memcpy(keyid,bn+n-8,8);
	}
    else
	{
	ops_fingerprint_t fingerprint;

	ops_fingerprint(&fingerprint,key);
	memcpy(keyid,fingerprint.fingerprint+fingerprint.length-8,8);
	}
    }
