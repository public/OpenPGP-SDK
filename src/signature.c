#include "signature.h"
#include "hash.h"
#include "memory.h"
#include "build.h"
#include <assert.h>

static unsigned char prefix_md5[]={ 0x30,0x20,0x30,0x0C,0x06,0x08,0x2A,0x86,
				    0x48,0x86,0xF7,0x0D,0x02,0x05,0x05,0x00,
				    0x04,0x10 };

static unsigned char prefix_sha1[]={ 0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0E,
				     0x03,0x02,0x1A,0x05,0x00,0x04,0x14 };

static ops_boolean_t rsa_verify(ops_hash_algorithm_t type,
				const unsigned char *hash,size_t hash_length,
				const ops_rsa_signature_t *sig,
				const ops_rsa_public_key_t *rsa)
    {
    unsigned char sigbuf[8192];
    unsigned char hashbuf[8192];
    int n;
    int keysize;
    unsigned char *prefix;
    int plen;

    keysize=(BN_num_bits(rsa->n)+7)/8;
    // RSA key can't be bigger than 65535 bits, so...
    assert(keysize <= sizeof hashbuf);
    assert(BN_num_bits(sig->sig) <= 8*sizeof sigbuf);
    BN_bn2bin(sig->sig,sigbuf);

    n=ops_rsa_public_decrypt(hashbuf,sigbuf,(BN_num_bits(sig->sig)+7)/8,rsa);

    if(n != keysize) // obviously, this includes error returns
	return ops_false;

    printf(" decrypt=%d ",n);
    hexdump(hashbuf,n);

    if(hashbuf[0] != 0 || hashbuf[1] != 1)
	return ops_false;

    switch(type)
	{
    case OPS_HASH_MD5: prefix=prefix_md5; plen=sizeof prefix_md5; break;
    case OPS_HASH_SHA1: prefix=prefix_sha1; plen=sizeof prefix_sha1; break;
    default: assert(0); break;
	}

    if(keysize-plen-hash_length < 10)
	return ops_false;

    for(n=2 ; n < keysize-plen-hash_length-1 ; ++n)
	if(hashbuf[n] != 0xff)
	    return ops_false;

    if(hashbuf[n++] != 0)
	return ops_false;

    if(memcmp(&hashbuf[n],prefix,plen)
       || memcmp(&hashbuf[n+plen],hash,hash_length))
	return ops_false;

    return ops_true;
    }

ops_boolean_t
ops_check_certification_signature(const ops_public_key_t *key,
				  const ops_user_id_t *id,
				  const ops_signature_t *sig,
				  const ops_public_key_t *signer,
				  const unsigned char *raw_packet)
    {
    ops_hash_t hash;
    ops_memory_t mem;
    unsigned char hashout[OPS_MAX_HASH];
    unsigned n;
    ops_boolean_t ret;

    switch(sig->hash_algorithm)
	{
    case OPS_HASH_MD5:
	ops_hash_md5(&hash);
	break;

    case OPS_HASH_SHA1:
	ops_hash_sha1(&hash);
	break;

    default:
	assert(0);
	}
    hash.init(&hash);

    memset(&mem,'\0',sizeof mem);
    ops_build_public_key(&mem,key,ops_false);

    hash_add_int(&hash,0x99,1);
    hash_add_int(&hash,mem.length,2);
    hash.add(&hash,mem.buf,mem.length);
    if(sig->version == OPS_SIG_V4)
	{
	hash_add_int(&hash,0xb4,1);
	hash_add_int(&hash,strlen(id->user_id),4);
	hash.add(&hash,id->user_id,strlen(id->user_id));
	hash.add(&hash,raw_packet+sig->v4_hashed_data_start,
		 sig->v4_hashed_data_length);
	hash_add_int(&hash,sig->version,1);
	hash_add_int(&hash,0xff,1);
	hash_add_int(&hash,sig->v4_hashed_data_length,4);
	}
    else
	{
	hash.add(&hash,id->user_id,strlen(id->user_id));
	hash_add_int(&hash,sig->type,1);
	hash_add_int(&hash,sig->creation_time,4);
	}

    n=hash.finish(&hash,hashout);
    printf(" hash=");
    //    hashout[0]=0;
    hexdump(hashout,n);

    switch(sig->key_algorithm)
	{
    case OPS_PKA_DSA:
	ret=ops_dsa_verify(hashout,n,&sig->signature.dsa,&signer->key.dsa);
	break;

    case OPS_PKA_RSA:
	ret=rsa_verify(sig->hash_algorithm,hashout,n,&sig->signature.rsa,
		       &signer->key.rsa);
	break;

    default:
	assert(0);
	}

    return ret;
    }
