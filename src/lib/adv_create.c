/** \file
 */

#include <openssl/cast.h>

#include <openpgpsdk/armour.h>
#include <openpgpsdk/create.h>
#include <openpgpsdk/keyring.h>
#include <openpgpsdk/memory.h>
#include <openpgpsdk/random.h>
#include <openpgpsdk/readerwriter.h>
#include "keyring_local.h"
#include <openpgpsdk/packet.h>
#include <openpgpsdk/util.h>
#include <openpgpsdk/std_print.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#ifndef WIN32
#include <unistd.h>
#endif

#include <openpgpsdk/final.h>

static int debug=0;

static ops_boolean_t writer_info_finalise(ops_error_t **errors,
                                          ops_writer_info_t *winfo);

/*
 * return true if OK, otherwise false
 */
static ops_boolean_t base_write(const void *src,unsigned length,
				ops_create_info_t *info)
    {
    return info->winfo.writer(src,length,&info->errors,&info->winfo);
    }

/**
 * \ingroup Create
 *
 * \param src
 * \param length
 * \param info
 * \return 1 if OK, otherwise 0
 */

ops_boolean_t ops_write(const void *src,unsigned length,
			ops_create_info_t *info)
    {
    return base_write(src,length,info);
    }

/**
 * \ingroup Create
 * \param n
 * \param length
 * \param info
 * \return ops_true if OK, otherwise ops_false
 */

ops_boolean_t ops_write_scalar(unsigned n,unsigned length,
			       ops_create_info_t *info)
    {
    while(length-- > 0)
	{
	unsigned char c[1];

	c[0]=n >> (length*8);
	if(!base_write(c,1,info))
	    return ops_false;
	}
    return ops_true;
    }

/** 
 * \ingroup Create
 * \param bn
 * \param info
 * \return 1 if OK, otherwise 0
 * \todo This statement about the return value is true based on the assumption
 *	that ops_true=1. Tidy this assumption up.
 */

ops_boolean_t ops_write_mpi(const BIGNUM *bn,ops_create_info_t *info)
    {
    unsigned char buf[8192];
    int bits=BN_num_bits(bn);

    assert(bits <= 65535);
    BN_bn2bin(bn,buf);
    return ops_write_scalar(bits,2,info)
	&& ops_write(buf,(bits+7)/8,info);
    }

/** 
 * \ingroup Create
 * \param tag
 * \param info
 * \return 1 if OK, otherwise 0
 */

ops_boolean_t ops_write_ptag(ops_content_tag_t tag,ops_create_info_t *info)
    {
    unsigned char c[1];

    c[0]=tag|OPS_PTAG_ALWAYS_SET|OPS_PTAG_NEW_FORMAT;

    return base_write(c,1,info);
    }

/** 
 * \ingroup Create
 * \param length
 * \param info
 * \return 1 if OK, otherwise 0
 */

ops_boolean_t ops_write_length(unsigned length,ops_create_info_t *info)
    {
    unsigned char c[2];

    if(length < 192)
	{
	c[0]=length;
	return base_write(c,1,info);
	}
    else if(length < 8384)
	{
	c[0]=((length-192) >> 8)+192;
	c[1]=(length-192)%256;
	return base_write(c,2,info);
	}
    return ops_write_scalar(0xff,1,info) && ops_write_scalar(length,4,info);
    }

/** 
 * \ingroup Create
 * \param length
 * \param type
 * \param info
 * \return 1 if OK, otherwise 0
 */

ops_boolean_t ops_write_ss_header(unsigned length,ops_content_tag_t type,
				  ops_create_info_t *info)
    {
    return ops_write_length(length,info)
	&& ops_write_scalar(type-OPS_PTAG_SIGNATURE_SUBPACKET_BASE,1,info);
    }

/* XXX: the general idea of _fast_ is that it doesn't copy stuff
 * the safe (i.e. non _fast_) version will, and so will also need to
 * be freed. */

/**
 * \ingroup Create
 *
 * ops_fast_create_user_id() sets id->user_id to the given user_id.
 * This is fast because it is only copying a char*. However, if user_id
 * is changed or freed in the future, this could have injurious results.
 * \param id
 * \param user_id
 */

void ops_fast_create_user_id(ops_user_id_t *id,unsigned char *user_id)
    {
    id->user_id=user_id;
    }

/**
 * \ingroup Create
 *
 * Writes a User Id from the information held in id and info
 *
 * \param id
 * \param info
 * \return Return value from ops_write() unless call to ops_write_ptag() or ops_write_length() failed before it was called, in which case returns 0
 * \todo tidy up that return value description!
 */
ops_boolean_t ops_write_struct_user_id(ops_user_id_t *id,
				       ops_create_info_t *info)
    {
    return ops_write_ptag(OPS_PTAG_CT_USER_ID,info)
	&& ops_write_length(strlen((char *)id->user_id),info)
	&& ops_write(id->user_id,strlen((char *)id->user_id),info);
    }

/**
 * \ingroup Create
 *
 * Write User Id
 * 
 * \param user_id
 * \param info
 *
 * \return return value from ops_write_struct_user_id()
 * \todo better descr of return value
 */
ops_boolean_t ops_write_user_id(const unsigned char *user_id,ops_create_info_t *info)
    {
    ops_user_id_t id;

    id.user_id=(unsigned char *)user_id;
    return ops_write_struct_user_id(&id,info);
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

static unsigned secret_key_length(const ops_secret_key_t *key)
    {
    int l;

    switch(key->public_key.algorithm)
	{
    case OPS_PKA_RSA:
	l=mpi_length(key->key.rsa.d)+mpi_length(key->key.rsa.p)
	    +mpi_length(key->key.rsa.q)+mpi_length(key->key.rsa.u);
	break;

    default:
	assert(!"unknown key algorithm");
	}

    return l+public_key_length(&key->public_key);
    }

/** 
 * \ingroup Create
 * \param key
 * \param time
 * \param n
 * \param e
*/
void ops_fast_create_rsa_public_key(ops_public_key_t *key,time_t time,
				    BIGNUM *n,BIGNUM *e)
    {
    key->version=4;
    key->creation_time=time;
    key->algorithm=OPS_PKA_RSA;
    key->key.rsa.n=n;
    key->key.rsa.e=e;
    }

/* Note that we support v3 keys here because they're needed for
 * for verification - the writer doesn't allow them, though */
static ops_boolean_t write_public_key_body(const ops_public_key_t *key,
					   ops_create_info_t *info)
    {
    if(!(ops_write_scalar(key->version,1,info)
	 && ops_write_scalar(key->creation_time,4,info)))
	return ops_false;

    if(key->version != 4 && !ops_write_scalar(key->days_valid,2,info))
	return ops_false;

    if(!ops_write_scalar(key->algorithm,1,info))
	return ops_false;

    switch(key->algorithm)
	{
    case OPS_PKA_DSA:
	return ops_write_mpi(key->key.dsa.p,info)
	    && ops_write_mpi(key->key.dsa.q,info)
	    && ops_write_mpi(key->key.dsa.g,info)
	    && ops_write_mpi(key->key.dsa.y,info);

    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:
	return ops_write_mpi(key->key.rsa.n,info)
	    && ops_write_mpi(key->key.rsa.e,info);

    case OPS_PKA_ELGAMAL:
	return ops_write_mpi(key->key.elgamal.p,info)
	    && ops_write_mpi(key->key.elgamal.g,info)
	    && ops_write_mpi(key->key.elgamal.y,info);

    default:
	assert(0);
	break;
	}

    /* not reached */
    return ops_false;
    }

typedef struct
    {
    ops_hash_algorithm_t hash_algorithm;
    ops_hash_t hash;
    unsigned char *hashed;
    } skey_checksum_arg_t;

static ops_boolean_t skey_checksum_writer(const unsigned char *src, const unsigned length, ops_error_t **errors, ops_writer_info_t *winfo)
    {
    skey_checksum_arg_t *arg=ops_writer_get_arg(winfo);
    ops_boolean_t rtn=ops_true;

    // add contents to hash
    arg->hash.add(&arg->hash, src, length);

    // write to next stacked writer
    rtn=ops_stacked_write(src,length,errors,winfo);

    // tidy up and return
    return rtn;
    }

static ops_boolean_t skey_checksum_finaliser(ops_error_t **errors __attribute__((unused)), ops_writer_info_t *winfo)
    {
    skey_checksum_arg_t *arg=ops_writer_get_arg(winfo);
    arg->hash.finish(&arg->hash, arg->hashed);
    return ops_true;
    }

static void skey_checksum_destroyer(ops_writer_info_t* winfo)
    {
    skey_checksum_arg_t *arg=ops_writer_get_arg(winfo);
    free(arg);
    }

void ops_push_skey_checksum_writer(ops_create_info_t *cinfo, ops_secret_key_t *skey)
    {
    //    OPS_USED(info);
    // XXX: push a SHA-1 checksum writer (and change s2k to 254).
    skey_checksum_arg_t *arg=ops_mallocz(sizeof *arg);

    // configure the arg
    arg->hash_algorithm=skey->hash_algorithm;
    arg->hashed=&skey->checkhash[0];

    // init the hash
    ops_hash_any(&arg->hash, arg->hash_algorithm);
    arg->hash.init(&arg->hash);

    ops_writer_push(cinfo, skey_checksum_writer, skey_checksum_finaliser, skey_checksum_destroyer, arg);
    }
 
/* Note that we support v3 keys here because they're needed for
 * for verification - the writer doesn't allow them, though */
static ops_boolean_t write_secret_key_body(const ops_secret_key_t *key,
                                           const unsigned char* passphrase,
                                           const size_t pplen,
					   ops_create_info_t *info)
    {
    /* RFC4880 Section 5.5.3 Secret-Key Packet Formats */

    ops_crypt_t crypt;
    ops_hash_t hash;
    unsigned char hashed[OPS_SHA1_HASH_SIZE];
    unsigned char session_key[CAST_KEY_LENGTH];
    unsigned int done=0;
    unsigned int i=0;

    if(!write_public_key_body(&key->public_key,info))
	return ops_false;

    assert(key->s2k_usage==OPS_S2KU_ENCRYPTED_AND_HASHED); /* = 254 */
    if(!ops_write_scalar(key->s2k_usage,1,info))
	return ops_false;
    
    assert(key->algorithm==OPS_SA_CAST5);
    if (!ops_write_scalar(key->algorithm,1,info))
        return ops_false;

    assert(key->s2k_specifier==OPS_S2KS_SIMPLE); // = 1 \todo should be salted or iterated-and-salted
    if (!ops_write_scalar(key->s2k_specifier,1,info))
        return ops_false;
    
    assert(key->hash_algorithm==OPS_HASH_SHA1);
    if (!ops_write_scalar(key->hash_algorithm,1,info))
        return ops_false;
    
    switch(key->s2k_specifier)
        {
    case OPS_S2KS_SIMPLE:
        // nothing more to do
        break;

        /* \todo
    case OPS_S2KS_SALTED:
    // 8-octet salt value
        break;

    case OPS_S2KS_ITERATED_AND_SALTED:
    // 8-octet salt value
    // 1-octet count
        break;
        */

    default:
        fprintf(stderr,"invalid/unsupported s2k specifier %d\n", key->s2k_specifier);
        assert(0);
        }

    if (!ops_write(&key->iv[0],ops_block_size(key->algorithm),info))
        return ops_false;
    
    /* create the session key for encrypting the algorithm-specific fields */

    switch(key->s2k_specifier)
        {
    case OPS_S2KS_SIMPLE:
        // RFC4880: section 3.7.1.1

        done=0;
        for (i=0; done<CAST_KEY_LENGTH; i++ )
            {
            unsigned int j=0;
            unsigned char zero=0;
            int needed=CAST_KEY_LENGTH-done;
            int use= needed < SHA_DIGEST_LENGTH ? needed : SHA_DIGEST_LENGTH;

            ops_hash_any(&hash, key->hash_algorithm);
            hash.init(&hash);
            
            // preload if iterating 
            for (j=0; j<i; j++)
                {
                hash.add(&hash, &zero, 1);
                }

            hash.add(&hash, passphrase, pplen);
            hash.finish(&hash, hashed);

            // if more in hash than is needed by session key, use the leftmost octets
            memcpy(session_key+(i*SHA_DIGEST_LENGTH), hashed, use);
            done += use;
            assert(done<=CAST_KEY_LENGTH);
            }

        break;

        /* \todo
    case OPS_S2KS_SALTED:
    // 8-octet salt value
        break;

    case OPS_S2KS_ITERATED_AND_SALTED:
    // 8-octet salt value
    // 1-octet count
        break;
        */

    default:
        fprintf(stderr,"invalid/unsupported s2k specifier %d\n", key->s2k_specifier);
        assert(0);
        }

    /* use this session key to encrypt */

    ops_crypt_any(&crypt,key->algorithm);
    crypt.set_iv(&crypt, key->iv);
    crypt.set_key(&crypt, session_key);
    ops_encrypt_init(&crypt);

    if (debug)
        {
        unsigned int i=0;
        fprintf(stderr,"\nWRITING:\niv=");
        for (i=0; i<ops_block_size(key->algorithm); i++)
            {
            fprintf(stderr, "%02x ", key->iv[i]);
            }
        fprintf(stderr,"\n");

        fprintf(stderr,"key=");
        for (i=0; i<CAST_KEY_LENGTH; i++)
            {
            fprintf(stderr, "%02x ", session_key[i]);
            }
        fprintf(stderr,"\n");

        ops_print_secret_key(OPS_PTAG_CT_SECRET_KEY,key);

        fprintf(stderr,"turning encryption on...\n");
        }

    ops_writer_push_encrypt_crypt(info, &crypt);

    switch(key->public_key.algorithm)
	{
	//    case OPS_PKA_DSA:
	//	return ops_write_mpi(key->key.dsa.x,info);

    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:

	if(!ops_write_mpi(key->key.rsa.d,info)
	   || !ops_write_mpi(key->key.rsa.p,info)
	   || !ops_write_mpi(key->key.rsa.q,info)
	   || !ops_write_mpi(key->key.rsa.u,info))
        {
        if (debug)
            { fprintf(stderr,"4 x mpi not written - problem\n"); }
	    return ops_false;
        }

	break;

	//    case OPS_PKA_ELGAMAL:
	//	return ops_write_mpi(key->key.elgamal.x,info);

    default:
	assert(0);
	break;
	}

    if(!ops_write(key->checkhash, OPS_CHECKHASH_SIZE, info))
        return ops_false;

    ops_writer_pop(info);
    
    return ops_true;
 }


ops_boolean_t ops_write_transferable_public_key(const ops_keydata_t *key, ops_boolean_t armoured, ops_create_info_t *info)
    {
    ops_boolean_t rtn;
    unsigned int i=0,j=0;

    if (armoured)
        { ops_writer_push_armoured(info, OPS_PGP_PUBLIC_KEY_BLOCK); }

    // public key
    rtn=ops_write_struct_public_key(&key->key.skey.public_key,info);
    if (rtn!=ops_true)
        return rtn;

    // TODO: revocation signatures go here

    // user ids and corresponding signatures
    for (i=0; i<key->nuids; i++)
        {
        ops_user_id_t* uid=&key->uids[i];

        rtn=ops_write_struct_user_id(uid, info);

        if (!rtn)
            return rtn;

        // find signature for this packet if it exists
        for (j=0; j<key->nsigs; j++)
            {
            sigpacket_t* sig=&key->sigs[i];
            if (!strcmp((char *)sig->userid->user_id, (char *)uid->user_id))
                {
                rtn=ops_write(sig->packet->raw, sig->packet->length, info);
                if (!rtn)
                    return !rtn;
                }
            }
        }

        // TODO: user attributes and corresponding signatures

        // subkey packets and corresponding signatures and optional revocation

    if (armoured)
        { 
        writer_info_finalise(&info->errors, &info->winfo);
        ops_writer_pop(info); 
        }

    return rtn;
    }

ops_boolean_t ops_write_transferable_secret_key(const ops_keydata_t *key, const unsigned char* passphrase, const size_t pplen, ops_boolean_t armoured, ops_create_info_t *info)
    {
    ops_boolean_t rtn;
    unsigned int i=0,j=0;

    if (armoured)
        { ops_writer_push_armoured(info,OPS_PGP_PRIVATE_KEY_BLOCK); }

    // public key
    rtn=ops_write_struct_secret_key(&key->key.skey,passphrase,pplen,info);
    if (rtn!=ops_true)
        return rtn;

    // TODO: revocation signatures go here

    // user ids and corresponding signatures
    for (i=0; i<key->nuids; i++)
        {
        ops_user_id_t* uid=&key->uids[i];

        rtn=ops_write_struct_user_id(uid, info);

        if (!rtn)
            return rtn;

        // find signature for this packet if it exists
        for (j=0; j<key->nsigs; j++)
            {
            sigpacket_t* sig=&key->sigs[i];
            if (!strcmp((char *)sig->userid->user_id, (char *)uid->user_id))
                {
                rtn=ops_write(sig->packet->raw, sig->packet->length, info);
                if (!rtn)
                    return !rtn;
                }
            }
        }

        // TODO: user attributes and corresponding signatures

        // subkey packets and corresponding signatures and optional revocation

    if (armoured)
        { 
        writer_info_finalise(&info->errors, &info->winfo);
        ops_writer_pop(info); 
        }

    return rtn;
    }

/**
 * \ingroup Create
 *
 * Writes a Public Key from the information held in "key" and "info"
 *
 * \param key
 * \param info
 * \return Return value from write_public_key_body() unless call to ops_write_ptag() or ops_write_length() failed before it was called, in which case returns 0
 * \todo tidy up that return value description!
 */
ops_boolean_t ops_write_struct_public_key(const ops_public_key_t *key,
					  ops_create_info_t *info)
    {
    assert(key->version == 4);

    return ops_write_ptag(OPS_PTAG_CT_PUBLIC_KEY,info)
	&& ops_write_length(1+4+1+public_key_length(key),info)
	&& write_public_key_body(key,info);
    }

/**
 * \ingroup Create
 *
 * Writes one RSA public key.
 *
 * The parameters for the public key are provided by "time", "n" and "e".
 *
 * This function expects "info" to specify a "writer" function to be used, for the
 * actual output.
 *
 * \sa See Detailed Description for usage.
 *
 * \param time Creation time
 * \param n RSA public modulus
 * \param e RSA public encryption exponent
 * \param info Writer setup
 *
 * \return result from ops_write_struct_public_key()
 * 
 * \todo get better definition of return values
 */

ops_boolean_t ops_write_rsa_public_key(time_t time,const BIGNUM *n,
				       const BIGNUM *e,
				       ops_create_info_t *info)
    {
    ops_public_key_t key;

    ops_fast_create_rsa_public_key(&key,time,DECONST(BIGNUM,n),
				   DECONST(BIGNUM,e));
    return ops_write_struct_public_key(&key,info);
    }

/**
 * \ingroup Create
 * \param out
 * \param key
 * \param make_packet
 */

void ops_build_public_key(ops_memory_t *out,const ops_public_key_t *key,
			  ops_boolean_t make_packet)
    {
    ops_create_info_t *info;

    info=ops_create_info_new();

    ops_memory_init(out,128);
    ops_writer_set_memory(info,out);

    write_public_key_body(key,info);

    if(make_packet)
	ops_memory_make_packet(out,OPS_PTAG_CT_PUBLIC_KEY);

    ops_create_info_delete(info);
    }

/**
 * \ingroup Create
 *
 * Create an RSA secret key structure. If a parameter is marked as
 * [OPTIONAL], then it can be omitted and will be calculated from
 * other parameters - or, in the case of e, will default to 0x10001.
 *
 * Parameters are _not_ copied, so will be freed if the structure is
 * freed.
 *
 * \param key The key structure to be initialised.
 * \param e The RSA parameter d (=e^-1 mod (p-1)(q-1)) [OPTIONAL]
 * \param p The RSA parameter p
 * \param q The RSA parameter q (q > p)
 * \param u The RSA parameter u (=p^-1 mod q) [OPTIONAL]
 * \param n The RSA public parameter n (=p*q) [OPTIONAL]
 * \param e The RSA public parameter e */

void ops_fast_create_rsa_secret_key(ops_secret_key_t *key,time_t time,
				    BIGNUM *d,BIGNUM *p,BIGNUM *q,BIGNUM *u,
				    BIGNUM *n,BIGNUM *e)
    {
    ops_fast_create_rsa_public_key(&key->public_key,time,n,e);

    // XXX: calculate optionals
    key->key.rsa.d=d;
    key->key.rsa.p=p;
    key->key.rsa.q=q;
    key->key.rsa.u=u;

    key->s2k_usage=OPS_S2KU_NONE;

    // XXX: sanity check and add errors...
    }

/**
 * \ingroup Create
 *
 * Writes a secret key.
 *
 * \param key The secret key
 * \param info
 * \return success
 */
ops_boolean_t ops_write_struct_secret_key(const ops_secret_key_t *key,
                                          const unsigned char* passphrase,
                                          const size_t pplen,
					  ops_create_info_t *info)
    {
    int length=0;

    assert(key->public_key.version == 4);

    // Ref: RFC4880 Section 5.5.3

    // public_key, excluding MPIs
    length += 1+4+1+1;

    // s2k usage
    length+=1;

    switch (key->s2k_usage)
        {
    case OPS_S2KU_NONE:
        // nothing to add
        break;

    case OPS_S2KU_ENCRYPTED_AND_HASHED: // 254
    case OPS_S2KU_ENCRYPTED: // 255

        // Ref: RFC4880 Section 3.7
        length+=1; // s2k_specifier

        switch(key->s2k_specifier)
            {
        case OPS_S2KS_SIMPLE:
            length+=1; // hash algorithm
            break;

        case OPS_S2KS_SALTED:
            length+=1+8; // hash algorithm + salt
            break;

        case OPS_S2KS_ITERATED_AND_SALTED:
            length+=1+8+1; // hash algorithm, salt + count
            break;

        default:
            assert(0);
            }
        break;

    default:
        assert(0);
        }

    // IV
    if (key->s2k_usage != 0)
        {
        length += ops_block_size(key->algorithm);
        }

    // checksum or hash
    switch (key->s2k_usage)
        {
    case 0:
    case 255:
        length += 2;
        break;

    case 254:
        length += 20;
        break;

    default:
        assert(0);
        }

    // secret key and public key MPIs
    length += secret_key_length(key);

    return ops_write_ptag(OPS_PTAG_CT_SECRET_KEY,info)
        //	&& ops_write_length(1+4+1+1+secret_key_length(key)+2,info)
        && ops_write_length(length,info)
        && write_secret_key_body(key,passphrase,pplen,info);
    }

/**
 * \ingroup Create
 *
 * Create a new ops_create_info_t structure.
 *
 * \return the new structure.
 */
ops_create_info_t *ops_create_info_new(void)
    { return ops_mallocz(sizeof(ops_create_info_t)); }

/* Note that we finalise from the top down, so we don't use writers below
 * that have already been finalised
 */
static ops_boolean_t writer_info_finalise(ops_error_t **errors,
					  ops_writer_info_t *winfo)
    {
    ops_boolean_t ret=ops_true;

    if(winfo->finaliser)
	{
	ret=winfo->finaliser(errors,winfo);
	winfo->finaliser=NULL;
	}
    if(winfo->next && !writer_info_finalise(errors,winfo->next))
	{
	winfo->finaliser=NULL;
	return ops_false;
	}
    return ret;
    }

static void writer_info_delete(ops_writer_info_t *winfo)
    {
    // we should have finalised before deleting
    assert(!winfo->finaliser);
    if(winfo->next)
	{
	writer_info_delete(winfo->next);
	free(winfo->next);
	winfo->next=NULL;
	}
    if(winfo->destroyer)
	{
	winfo->destroyer(winfo);
	winfo->destroyer=NULL;
	}
    winfo->writer=NULL;
    }

/**
 * \ingroup Create
 *
 * Delete an ops_create_info_t structure. If a writer is active, then
 * that is also deleted.
 *
 * \param info the structure to be deleted.
 */
void ops_create_info_delete(ops_create_info_t *info)
    {
    writer_info_delete(&info->winfo);
    free(info);
    }

typedef struct
    {
    int fd;
    } writer_fd_arg_t;

static ops_boolean_t fd_writer(const unsigned char *src,unsigned length,
			       ops_error_t **errors,
			       ops_writer_info_t *winfo)
    {
    writer_fd_arg_t *arg=ops_writer_get_arg(winfo);
    int n=write(arg->fd,src,length);

    if(n == -1)
	{
	OPS_SYSTEM_ERROR_1(errors,OPS_E_W_WRITE_FAILED,"write",
			   "file descriptor %d",arg->fd);
	return ops_false;
	}

    if((unsigned)n != length)
	{
	OPS_ERROR_1(errors,OPS_E_W_WRITE_TOO_SHORT,
		    "file descriptor %d",arg->fd);
	return ops_false;
	}

    return ops_true;
    }

static void fd_destroyer(ops_writer_info_t *winfo)
    {
    free(ops_writer_get_arg(winfo));
    }

/**
 * \ingroup Create
 *
 * Set the writer in info to be a stock writer that writes to a file
 * descriptor. If another writer has already been set, then that is
 * first destroyed.
 * 
 * \param info The info structure
 * \param fd The file descriptor
 *
 */

void ops_writer_set_fd(ops_create_info_t *info,int fd)
    {
    writer_fd_arg_t *arg=malloc(sizeof *arg);

    arg->fd=fd;
    ops_writer_set(info,fd_writer,NULL,fd_destroyer,arg);
    }

/**
 * \ingroup Create
 *
 * Set a writer in info. There should not be another writer set.
 *
 * \param info The info structure
 * \param writer The writer
 * \param destroyer The destroyer
 * \param arg The argument for the writer and destroyer
 */
void ops_writer_set(ops_create_info_t *info,
		    ops_writer_t *writer,
		    ops_writer_finaliser_t *finaliser,
		    ops_writer_destroyer_t *destroyer,
		    void *arg)
    {
    assert(!info->winfo.writer);
    info->winfo.writer=writer;
    info->winfo.finaliser=finaliser;
    info->winfo.destroyer=destroyer;
    info->winfo.arg=arg;
    }

/**
 * \ingroup Create
 *
 * Push a writer in info. There must already be another writer set.
 *
 * \param info The info structure
 * \param writer The writer
 * \param destroyer The destroyer
 * \param arg The argument for the writer and destroyer
 */
void ops_writer_push(ops_create_info_t *info,
		     ops_writer_t *writer,
		     ops_writer_finaliser_t *finaliser,
		     ops_writer_destroyer_t *destroyer,
		     void *arg)
    {
    ops_writer_info_t *copy=ops_mallocz(sizeof *copy);

    assert(info->winfo.writer);
    *copy=info->winfo;
    info->winfo.next=copy;

    info->winfo.writer=writer;
    info->winfo.finaliser=finaliser;
    info->winfo.destroyer=destroyer;
    info->winfo.arg=arg;
    }

void ops_writer_pop(ops_create_info_t *info)
    { 
    ops_writer_info_t *next;

    // Make sure the finaliser has been called.
    assert(!info->winfo.finaliser);
    // Make sure this is a stacked writer
    assert(info->winfo.next);
    if(info->winfo.destroyer)
	info->winfo.destroyer(&info->winfo);

    next=info->winfo.next;
    info->winfo=*next;

    free(next);
    }

/**
 * \ingroup Create
 *
 * Close the writer currently set in info.
 *
 * \param info The info structure
 */
ops_boolean_t ops_writer_close(ops_create_info_t *info)
    {
    ops_boolean_t ret=writer_info_finalise(&info->errors,&info->winfo);

    writer_info_delete(&info->winfo);

    return ret;
    }

/**
 * \ingroup Create
 *
 * Get the arg supplied to ops_create_info_set_writer().
 *
 * \param winfo The writer_info structure
 * \return The arg
 */
void *ops_writer_get_arg(ops_writer_info_t *winfo)
    { return winfo->arg; }

/**
 * \ingroup Create
 *
 * Write to the next writer down in the stack.
 *
 * \param src The data to write.
 * \param length The length of src.
 * \param flags The writer flags.
 * \param errors A place to store errors.
 * \param info The writer_info structure.
 * \return Success - if ops_false, then errors should contain the error.
 */
ops_boolean_t ops_stacked_write(const void *src,unsigned length,
				ops_error_t **errors,ops_writer_info_t *winfo)
    {
    return winfo->next->writer(src,length,errors,winfo->next);
    }

/**
 * \ingroup Create
 *
 * Free the arg. Many writers just have a malloc()ed lump of storage, this
 * function releases it.
 *
 * \param winfo the info structure.
 */
void ops_writer_generic_destroyer(ops_writer_info_t *winfo)
    { free(ops_writer_get_arg(winfo)); }

/**
 * \ingroup Create
 *
 * A writer that just writes to the next one down. Useful for when you
 * want to insert just a finaliser into the stack.
 */
ops_boolean_t ops_writer_passthrough(const unsigned char *src,
				     unsigned length,
				     ops_error_t **errors,
				     ops_writer_info_t *winfo)
    { return ops_stacked_write(src,length,errors,winfo); }


ops_boolean_t ops_calc_session_key_checksum(ops_pk_session_key_t *session_key, unsigned char *cs)
    {
    unsigned int i=0;
    unsigned long checksum=0;

    if (!ops_is_sa_supported(session_key->symmetric_algorithm))
        return ops_false;

    for (i=0; i<ops_key_size(session_key->symmetric_algorithm); i++)
        {
        checksum+=session_key->key[i];
        }
    checksum = checksum % 65536;

    cs[0]=checksum >> 8;
    cs[1]=checksum & 0xFF;

    return ops_true;
    //    fprintf(stderr,"\nm buf checksum: ");
    //    fprintf(stderr," %2x",cs[0]);
    //    fprintf(stderr," %2x\n",cs[1]);
    }    

static ops_boolean_t create_unencoded_m_buf(ops_pk_session_key_t *session_key, unsigned char *m_buf)
    {
    int i=0;
    //    unsigned long checksum=0;

    // m_buf is the buffer which will be encoded in PKCS#1 block
    // encoding to form the "m" value used in the 
    // Public Key Encrypted Session Key Packet
    // as defined in RFC Section 5.1 "Public-Key Encrypted Session Key Packet"

    m_buf[0]=session_key->symmetric_algorithm;

    assert(session_key->symmetric_algorithm==OPS_SA_CAST5);
    for (i=0; i<CAST_KEY_LENGTH; i++)
        {
        m_buf[1+i]=session_key->key[i];
        }

    return(ops_calc_session_key_checksum(session_key, m_buf+1+CAST_KEY_LENGTH));
    }

ops_boolean_t encode_m_buf(const unsigned char *M, size_t mLen,
                           const ops_public_key_t *pkey,
                           unsigned char* EM
)
    {
    unsigned int k;
    unsigned i;

    // implementation of EME-PKCS1-v1_5-ENCODE, as defined in OpenPGP RFC
    
    assert(pkey->algorithm == OPS_PKA_RSA);

    k=BN_num_bytes(pkey->key.rsa.n);
    assert(mLen <= k-11);
    if (mLen > k-11)
        {
        fprintf(stderr,"message too long\n");
        return ops_false;
        }

    // these two bytes defined by RFC
    EM[0]=0x00;
    EM[1]=0x02;

    // add non-zero random bytes of length k - mLen -3
    for(i=2 ; i < k-mLen-1 ; ++i)
        do
            ops_random(EM+i, 1);
        while(EM[i] == 0);

    assert (i >= 8+2);

    EM[i++]=0;

    memcpy(EM+i, M, mLen);
    

    if (debug)
        {
        unsigned int i=0;
        fprintf(stderr,"Encoded Message: \n");
        for (i=0; i<mLen; i++)
            fprintf(stderr,"%2x ", EM[i]);
        fprintf(stderr,"\n");
        }

    return ops_true;
    }

ops_pk_session_key_t *ops_create_pk_session_key(const ops_keydata_t *key)
    {
    /*
     * Creates a random session key and encrypts it for the given key
     *
     * Session Key is for use with a SK algo, 
     * can be any, we're hardcoding CAST5 for now
     *
     * Encryption used is PK, 
     * can be any, we're hardcoding RSA for now
     */

    const ops_public_key_t* pub_key=ops_get_public_key_from_data(key);
#define SZ_UNENCODED_M_BUF CAST_KEY_LENGTH+1+2
    unsigned char unencoded_m_buf[SZ_UNENCODED_M_BUF];

    const size_t sz_encoded_m_buf=BN_num_bytes(pub_key->key.rsa.n);
    unsigned char* encoded_m_buf = ops_mallocz(sz_encoded_m_buf);

    ops_pk_session_key_t *session_key=ops_mallocz(sizeof *session_key);

    assert(key->type == OPS_PTAG_CT_PUBLIC_KEY);
    session_key->version=OPS_PKSK_V3;
    memcpy(session_key->key_id, key->key_id, sizeof session_key->key_id);

    if (debug)
        {
        unsigned int i=0;
        fprintf(stderr,"Encrypting for RSA key id : ");
        for (i=0; i<sizeof session_key->key_id; i++)
            fprintf(stderr,"%2x ", key->key_id[i]);
        fprintf(stderr,"\n");
        }

    assert(key->key.pkey.algorithm == OPS_PKA_RSA);
    session_key->algorithm=key->key.pkey.algorithm;

    // \todo allow user to specify other algorithm
    session_key->symmetric_algorithm=OPS_SA_CAST5;
    ops_random(session_key->key, CAST_KEY_LENGTH);

    if (debug)
        {
        unsigned int i=0;
        fprintf(stderr,"CAST5 session key created (len=%d):\n ", CAST_KEY_LENGTH);
        for (i=0; i<CAST_KEY_LENGTH; i++)
            fprintf(stderr,"%2x ", session_key->key[i]);
        fprintf(stderr,"\n");
        }

    if (create_unencoded_m_buf(session_key, &unencoded_m_buf[0])==ops_false)
        {
        free(encoded_m_buf);
        return NULL;
        }

    if (debug)
        {
        unsigned int i=0;
        printf("unencoded m buf:\n");
        for (i=0; i<SZ_UNENCODED_M_BUF; i++)
            printf("%2x ", unencoded_m_buf[i]);
        printf("\n");
        }
    encode_m_buf(&unencoded_m_buf[0], SZ_UNENCODED_M_BUF, pub_key, &encoded_m_buf[0]);
    
    // and encrypt it
    if(!ops_rsa_encrypt_mpi(encoded_m_buf, sz_encoded_m_buf, pub_key, &session_key->parameters))
        {
        free (encoded_m_buf);
        return NULL;
        }

    free(encoded_m_buf);
    return session_key;
    }

ops_boolean_t ops_write_pk_session_key(ops_create_info_t *info,
				       ops_pk_session_key_t *pksk)
    {
    assert(pksk);
    assert(pksk->algorithm == OPS_PKA_RSA);

    return ops_write_ptag(OPS_PTAG_CT_PK_SESSION_KEY, info)
	&& ops_write_length(1 + 8 + 1 + BN_num_bytes(pksk->parameters.rsa.encrypted_m) + 2, info)
	&& ops_write_scalar(pksk->version, 1, info)
	&& ops_write(pksk->key_id, 8, info)
	&& ops_write_scalar(pksk->algorithm, 1, info)
	&& ops_write_mpi(pksk->parameters.rsa.encrypted_m, info)
        //??	&& ops_write_scalar(0, 2, info);
        ;
    }

ops_boolean_t ops_write_mdc(const unsigned char *hashed,
                            ops_create_info_t* info)
    {
    // write it out
    return ops_write_ptag(OPS_PTAG_CT_MDC, info)
        && ops_write_length(OPS_SHA1_HASH_SIZE,info)
        && ops_write(hashed, OPS_SHA1_HASH_SIZE, info);
    }

// RENAMED from ops_boolean_t ops_write_literal_data(const unsigned char *data, 
ops_boolean_t ops_write_literal_data_from_buf(const unsigned char *data, 
                                     const int maxlen, 
                                     const ops_literal_data_type_t type,
                                     ops_create_info_t *info)
    {
    // \todo add filename 
    // \todo add date
    // \todo do we need to check text data for <cr><lf> line endings ?
    return ops_write_ptag(OPS_PTAG_CT_LITERAL_DATA, info)
        && ops_write_length(1+1+4+maxlen,info)
        && ops_write_scalar(type, 1, info)
        && ops_write_scalar(0, 1, info)
        && ops_write_scalar(0, 4, info)
        && ops_write(data, maxlen, info);
    }

ops_boolean_t ops_write_literal_data_from_file(const char *filename, 
                                     const ops_literal_data_type_t type,
                                     ops_create_info_t *info)
    {
    size_t initial_size=1024;
    int fd=0;
    ops_boolean_t rtn;
    unsigned char buf[1024];
    ops_memory_t* mem=NULL;
    size_t len=0;

#ifdef WIN32
    fd=open(filename,O_RDONLY | O_BINARY);
#else
    fd=open(filename,O_RDONLY);
#endif
    if (fd < 0)
        return ops_false;

    mem=ops_mallocz(sizeof mem);
    ops_memory_init(mem,initial_size);
    for (;;)
        {
        int n=0;
        n=read(fd,buf,1024);
        if (!n)
            break;
        ops_memory_add(mem, &buf[0], n);
        }
    close(fd);    
    // \todo add date
    // \todo do we need to check text data for <cr><lf> line endings ?
    len=ops_memory_get_length(mem);
    rtn=ops_write_ptag(OPS_PTAG_CT_LITERAL_DATA, info)
        && ops_write_length(1+1+4+len,info)
        && ops_write_scalar(type, 1, info)
        && ops_write_scalar(0, 1, info)
        && ops_write_scalar(0, 4, info)
        && ops_write(ops_memory_get_data(mem), len, info);

    ops_memory_free(mem);
    return rtn;
    }

ops_memory_t* ops_write_buf_from_file(const char *filename)
    {
    size_t initial_size=1024;
    int fd=0;
    unsigned char buf[1024];
    ops_memory_t* mem=NULL;

#ifdef WIN32
    fd=open(filename,O_RDONLY | O_BINARY);
#else
    fd=open(filename,O_RDONLY);
#endif
    if (fd < 0)
        return ops_false;

    mem=ops_mallocz(sizeof mem);
    ops_memory_init(mem,initial_size);
    for (;;)
        {
        int n=0;
        n=read(fd,buf,1024);
        if (!n)
            break;
        ops_memory_add(mem, &buf[0], n);
        }
    close(fd);    
    return mem;
    }

int ops_write_file_from_buf(const char *filename, const char* buf, const size_t len)
    {
    int fd=0;
    size_t n=0;

#ifdef WIN32
    fd=open(filename,O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
#else
    fd=open(filename,O_WRONLY | O_CREAT | O_EXCL, 0600);
#endif
    if (fd < 0)
        {
        perror(NULL); 
        return 0;
        }

    n=write(fd,buf,len);
    if (n!=len)
        return 0;

    if(!close(fd))
        return 1;

    return 0;
    }

ops_boolean_t ops_write_symmetrically_encrypted_data(const unsigned char *data, 
                                                     const int len, 
                                                     ops_create_info_t *info)
    {
    int done=0;
    ops_crypt_t crypt_info;
    int encrypted_sz=0;// size of encrypted data
    unsigned char *encrypted=(unsigned char *)NULL; // buffer to write encrypted data to
    
    // \todo assume AES256 for now
    ops_crypt_any(&crypt_info, OPS_SA_AES_256);
    ops_encrypt_init(&crypt_info);

    encrypted_sz=len+crypt_info.blocksize+2;
    encrypted=ops_mallocz(encrypted_sz);

    done=ops_encrypt_se(&crypt_info, encrypted, data, len);
    assert(done==len);
    //    printf("len=%d, done: %d\n", len, done);

    return ops_write_ptag(OPS_PTAG_CT_SE_DATA, info)
        && ops_write_length(1+encrypted_sz,info)
        && ops_write(data, len, info);
    }

ops_boolean_t ops_write_one_pass_sig(const ops_secret_key_t* skey,
                                     const ops_hash_algorithm_t hash_alg,
                                     const ops_sig_type_t sig_type,
                                     ops_create_info_t* info)
    {
    unsigned char keyid[OPS_KEY_ID_SIZE];
    if (debug)
        { fprintf(stderr,"calling ops_keyid in write_one_pass_sig: this calls sha1_init\n"); }
    ops_keyid(keyid,&skey->public_key);

    return ops_write_ptag(OPS_PTAG_CT_ONE_PASS_SIGNATURE, info)
        && ops_write_length(1+1+1+1+8+1, info)
        && ops_write_scalar (3, 1, info) // version
        && ops_write_scalar (sig_type, 1, info)
        && ops_write_scalar (hash_alg, 1, info)
        && ops_write_scalar (skey->public_key.algorithm,  1, info)
        && ops_write(keyid, 8, info)
        && ops_write_scalar (1, 1, info);
    }



// EOF
