/** \file
 */

#include "create.h"
#include "util.h"
#include "build.h"
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
    unsigned char c[2];

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
    return ops_write_scalar(0xff,1,opt) && ops_write_scalar(length,4,opt);
    }

ops_boolean_t ops_write_ss_header(unsigned length,ops_content_tag_t type,
				  ops_create_options_t *opt)
    {
    return ops_write_length(length,opt)
	&& ops_write_scalar(type-OPS_PTAG_SIGNATURE_SUBPACKET_BASE,1,opt);
    }

// XXX: the general idea of _fast_ is that it doesn't copy stuff
// the safe (i.e. non _fast_) version will, and so will also need to
// be freed.

/**
 * \ingroup Create
 *
 * ops_fast_create_user_id() sets id->user_id to the given "user_id".
 * This is fast because it is only copying a char*. However, if "user_id"
 * is changed or freed in the future, this could have injurious results.
 * \param id
 * \param user_id
 */

void ops_fast_create_user_id(ops_user_id_t *id,char *user_id)
    {
    id->user_id=user_id;;
    }

/**
 * \ingroup Create
 *
 * Writes a User Id from the information held in #id and #opt
 *
 * \param id
 * \param opt
 * \return Return value from ops_write() unless call to ops_write_ptag() or ops_write_length() failed before it was called, in which case returns 0
 * \todo tidy up that return value description!
 */
ops_boolean_t ops_write_struct_user_id(ops_user_id_t *id,
				       ops_create_options_t *opt)
    {
    return ops_write_ptag(OPS_PTAG_CT_USER_ID,opt)
	&& ops_write_length(strlen(id->user_id),opt)
	&& ops_write(id->user_id,strlen(id->user_id),opt);
    }

/**
 * \ingroup Create
 *
 * Write User Id
 * 
 * \param user_id
 * \param opt
 *
 * \return return value from ops_write_struct_user_id()
 * \todo better descr of return value
 */
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

void ops_fast_create_rsa_public_key(ops_public_key_t *key,time_t time,
				    BIGNUM *n,BIGNUM *e)
    {
    key->version=4;
    key->creation_time=time;
    key->algorithm=OPS_PKA_RSA;
    key->key.rsa.n=n;
    key->key.rsa.e=e;
    }

// Note that we support v3 keys here because they're needed for
// for verification - the writer doesn't allow them, though
static int write_public_key_body(const ops_public_key_t *key,
				  ops_create_options_t *opt)
    {
    if(!(ops_write_scalar(key->version,1,opt)
	 && ops_write_scalar(key->creation_time,4,opt)))
	return ops_false;

    if(key->version != 4 && !ops_write_scalar(key->days_valid,2,opt))
	return ops_false;

    if(!ops_write_scalar(key->algorithm,1,opt))
	return ops_false;

    switch(key->algorithm)
	{
    case OPS_PKA_DSA:
	return ops_write_mpi(key->key.dsa.p,opt)
	    && ops_write_mpi(key->key.dsa.q,opt)
	    && ops_write_mpi(key->key.dsa.g,opt)
	    && ops_write_mpi(key->key.dsa.y,opt);

    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:
	return ops_write_mpi(key->key.rsa.n,opt)
	    && ops_write_mpi(key->key.rsa.e,opt);

    case OPS_PKA_ELGAMAL:
	return ops_write_mpi(key->key.elgamal.p,opt)
	    && ops_write_mpi(key->key.elgamal.g,opt)
	    && ops_write_mpi(key->key.elgamal.y,opt);

    default:
	assert(0);
	break;
	}

    /* not reached */
    return ops_false;
    }

/**
 * \ingroup Create
 *
 * Writes a Public Key from the information held in "key" and "opt"
 *
 * \param key
 * \param opt
 * \return Return value from write_public_key_body() unless call to ops_write_ptag() or ops_write_length() failed before it was called, in which case returns 0
 * \todo tidy up that return value description!
 */
ops_boolean_t ops_write_struct_public_key(const ops_public_key_t *key,
					  ops_create_options_t *opt)
    {
    assert(key->version == 4);

    return ops_write_ptag(OPS_PTAG_CT_PUBLIC_KEY,opt)
	&& ops_write_length(1+4+1+public_key_length(key),opt)
	&& write_public_key_body(key,opt);
    }

/**
 * \ingroup Create
 *
 * Writes one RSA public key.
 *
 * The parameters for the public key are provided by "time", "n" and "e".
 *
 * This function expects "opt" to specify a "writer" function to be used, for the
 * actual output.
 *
 * \sa See Detailed Description for usage.
 *
 * \param time Creation time
 * \param n RSA public modulus
 * \param e RSA public encryption exponent
 * \param opt Writer setup
 *
 * \return result from ops_write_struct_public_key()
 * 
 * \todo get better definition of return values
 */

ops_boolean_t ops_write_rsa_public_key(time_t time,const BIGNUM *n,
				       const BIGNUM *e,
				       ops_create_options_t *opt)
    {
    ops_public_key_t key;

    ops_fast_create_rsa_public_key(&key,time,DECONST(BIGNUM,n),
				   DECONST(BIGNUM,e));
    return ops_write_struct_public_key(&key,opt);
    }

void ops_build_public_key(ops_memory_t *out,const ops_public_key_t *key,
			  ops_boolean_t make_packet)
    {
    ops_create_options_t opt;

    ops_memory_init(out,128);
    opt.writer=ops_writer_memory;
    opt.arg=out;

    write_public_key_body(key,&opt);

    if(make_packet)
	ops_memory_make_packet(out,OPS_PTAG_CT_PUBLIC_KEY);
    }
