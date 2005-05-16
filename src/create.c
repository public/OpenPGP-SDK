#include "create.h"
#include "util.h"
#include <string.h>
#include <assert.h>

static int base_write(const void *src,unsigned length,
		       ops_create_options_t *opt)
    {
    return opt->writer(src,length,0,opt->arg) == OPS_W_OK;
    }

ops_boolean_t ops_write(const void *src,unsigned length,
			ops_create_options_t *opt)
    {
    return base_write(src,length,opt);
    }

ops_boolean_t ops_write_scalar(unsigned n,unsigned length,
			       ops_create_options_t *opt)
    {
    while(length-- > 0)
	{
	unsigned char c[1];

	c[0]=n >> (length*8);
	if(!base_write(c,1,opt))
	    return ops_false;
	}
    return ops_true;
    }

ops_boolean_t ops_write_mpi(const BIGNUM *bn,ops_create_options_t *opt)
    {
    unsigned char buf[8192];
    int bits=BN_num_bits(bn);

    assert(bits <= 65535);
    BN_bn2bin(bn,buf);
    return ops_write_scalar(bits,2,opt)
	&& ops_write(buf,(bits+7)/8,opt);
    }

ops_boolean_t ops_write_ptag(ops_content_tag_t tag,ops_create_options_t *opt)
    {
    unsigned char c[1];

    c[0]=tag|OPS_PTAG_ALWAYS_SET|OPS_PTAG_NEW_FORMAT;

    return base_write(c,1,opt);
    }

ops_boolean_t ops_write_length(unsigned length,ops_create_options_t *opt)
    {
    unsigned char c[5];

    if(length < 192)
	{
	c[0]=length;
	return base_write(c,1,opt);
	}
    else if(length < 8384)
	{
	c[0]=((length-192) >> 8)+192;
	c[1]=(length-192)%256;
	return base_write(c,2,opt);
	}
    c[0]=0xff;
    return ops_write_scalar(length,4,opt);
    }

ops_boolean_t ops_write_struct_user_id(ops_user_id_t *id,
				       ops_create_options_t *opt)
    {
    return ops_write_ptag(OPS_PTAG_CT_USER_ID,opt)
	&& ops_write_length(strlen(id->user_id),opt)
	&& ops_write(id->user_id,strlen(id->user_id),opt);
    }

ops_boolean_t ops_write_user_id(const char *user_id,ops_create_options_t *opt)
    {
    ops_user_id_t id;

    id.user_id=(char *)user_id;
    return ops_write_struct_user_id(&id,opt);
    }

static unsigned mpi_length(const BIGNUM *bn)
    {
    return 2+(BN_num_bits(bn)+7)/8;
    }

static unsigned public_key_length(const ops_public_key_t *key)
    {
    switch(key->algorithm)
	{
    case OPS_PKA_RSA:
	return mpi_length(key->key.rsa.n)+mpi_length(key->key.rsa.e);

    default:
	assert(!"unknown key algorithm");
	}
    /* not reached */
    return 0;
    }

ops_boolean_t ops_write_struct_public_key(const ops_public_key_t *key,
					  ops_create_options_t *opt)
    {
    assert(key->version == 4);

    if(!(ops_write_ptag(OPS_PTAG_CT_PUBLIC_KEY,opt)
	 && ops_write_length(1+4+1+public_key_length(key),opt)
	 && ops_write_scalar(key->version,1,opt)
	 && ops_write_scalar(key->creation_time,4,opt)
	 && ops_write_scalar(key->algorithm,1,opt)))
	return ops_false;

    switch(key->algorithm)
	{
    case OPS_PKA_RSA:
	return ops_write_mpi(key->key.rsa.n,opt)
	    && ops_write_mpi(key->key.rsa.e,opt);

    default:
	assert(!"unknown key algorithm");
	}

    /* not reached */
    return ops_false;
    }

ops_boolean_t ops_write_rsa_public_key(time_t time,const BIGNUM *n,
				       const BIGNUM *e,
				       ops_create_options_t *opt)
    {
    ops_public_key_t key;

    key.version=4;
    key.creation_time=time;
    key.algorithm=OPS_PKA_RSA;
    key.key.rsa.n=DECONST(BIGNUM,n);
    key.key.rsa.e=DECONST(BIGNUM,e);
    return ops_write_struct_public_key(&key,opt);
    }
