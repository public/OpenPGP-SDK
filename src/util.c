#include "packet.h"
#include "util.h"
#include "hash.h"
#include <stdio.h>
#include <assert.h>

void hexdump(const unsigned char *src,size_t length)
    {
    while(length--)
	printf("%02X",*src++);
    }

void ops_fingerprint(ops_fingerprint_t *fp,const ops_public_key_t *key)
    {
    if(key->version == 3)
	{
	unsigned char *bn;
	int n;
	ops_hash_t md5;

	assert(key->algorithm == OPS_PKA_RSA);

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
	assert(0);
	}
    }

void ops_keyid(unsigned char keyid[8],const ops_public_key_t *key)
    {
    if(key->version == 3)
	{
	unsigned char *bn;
	int n=BN_num_bytes(key->key.rsa.n);

	assert(key->algorithm == OPS_PKA_RSA);
	bn=alloca(n);
	BN_bn2bin(key->key.rsa.n,bn);
	memcpy(keyid,bn+n-8,8);
	}
    else
	{
	
	assert(0);
	}
    }
