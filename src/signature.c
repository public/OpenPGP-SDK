/** \file
 */

#include <openpgpsdk/signature.h>
#include <openpgpsdk/crypto.h>
#include <openpgpsdk/create.h>
#include <assert.h>
#include <string.h>

static unsigned char prefix_md5[]={ 0x30,0x20,0x30,0x0C,0x06,0x08,0x2A,0x86,
				    0x48,0x86,0xF7,0x0D,0x02,0x05,0x05,0x00,
				    0x04,0x10 };

static unsigned char prefix_sha1[]={ 0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0E,
				     0x03,0x02,0x1A,0x05,0x00,0x04,0x14 };

// XXX: both this and verify would be clearer if the signature were
// treated as an MPI.
static void rsa_sign(ops_hash_t *hash,const ops_rsa_public_key_t *rsa,
		     const ops_rsa_secret_key_t *srsa,
		     ops_create_info_t *opt)
    {
    unsigned char hashbuf[8192];
    unsigned char sigbuf[8192];
    unsigned keysize;
    unsigned hashsize;
    unsigned n;
    unsigned t;
    BIGNUM *bn;

    // XXX: we assume hash is sha-1 for now
    hashsize=20+sizeof prefix_sha1;

    keysize=(BN_num_bits(rsa->n)+7)/8;
    assert(keysize <= sizeof hashbuf);
    assert(10+hashsize <= keysize);

    hashbuf[0]=1;
    for(n=1 ; n < keysize-hashsize-1 ; ++n)
	hashbuf[n]=0xff;
    hashbuf[n++]=0;

    memcpy(&hashbuf[n],prefix_sha1,sizeof prefix_sha1);
    n+=sizeof prefix_sha1;

    t=hash->finish(hash,&hashbuf[n]);
    assert(t == 20);

    ops_write(&hashbuf[n],2,opt);

    n+=t;
    assert(n == keysize);

    t=ops_rsa_private_encrypt(sigbuf,hashbuf,keysize,srsa,rsa);
    bn=BN_bin2bn(sigbuf,t,NULL);
    ops_write_mpi(bn,opt);
    BN_free(bn);
    }

static ops_boolean_t rsa_verify(ops_hash_algorithm_t type,
				const unsigned char *hash,size_t hash_length,
				const ops_rsa_signature_t *sig,
				const ops_rsa_public_key_t *rsa)
    {
    unsigned char sigbuf[8192];
    unsigned char hashbuf[8192];
    unsigned n;
    unsigned keysize;
    unsigned char *prefix;
    int plen;

    keysize=BN_num_bytes(rsa->n);
    /* RSA key can't be bigger than 65535 bits, so... */
    assert(keysize <= sizeof hashbuf);
    assert((unsigned)BN_num_bits(sig->sig) <= 8*sizeof sigbuf);
    BN_bn2bin(sig->sig,sigbuf);

    n=ops_rsa_public_decrypt(hashbuf,sigbuf,(BN_num_bits(sig->sig)+7)/8,rsa);

    if(n != keysize) // obviously, this includes error returns
	return ops_false;

    printf(" decrypt=%d ",n);
    hexdump(hashbuf,n);

    // XXX: why is there a leading 0? The first byte should be 1...
    // XXX: because the decrypt should use keysize and not sigsize?
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

static void hash_add_key(ops_hash_t *hash,const ops_public_key_t *key)
    {
    ops_memory_t mem;

    memset(&mem,'\0',sizeof mem);
    ops_build_public_key(&mem,key,ops_false);

    ops_hash_add_int(hash,0x99,1);
    ops_hash_add_int(hash,mem.length,2);
    hash->add(hash,mem.buf,mem.length);

    ops_memory_release(&mem);
    }

static void common_init_signature(ops_hash_t *hash,const ops_signature_t *sig)
    {
    ops_hash_any(hash,sig->hash_algorithm);
    hash->init(hash);
    }

static void init_signature(ops_hash_t *hash,const ops_signature_t *sig,
			   const ops_public_key_t *key)
    {
    common_init_signature(hash,sig);
    hash_add_key(hash,key);
    }

static void hash_add_trailer(ops_hash_t *hash,const ops_signature_t *sig,
			     const unsigned char *raw_packet)
    {
    if(sig->version == OPS_SIG_V4)
	{
	if(raw_packet)
	    hash->add(hash,raw_packet+sig->v4_hashed_data_start,
		      sig->v4_hashed_data_length);
	ops_hash_add_int(hash,sig->version,1);
	ops_hash_add_int(hash,0xff,1);
	ops_hash_add_int(hash,sig->v4_hashed_data_length,4);
	}
    else
	{
	ops_hash_add_int(hash,sig->type,1);
	ops_hash_add_int(hash,sig->creation_time,4);
	}
    }

static ops_boolean_t check_signature(const unsigned char *hash,unsigned length,
				     const ops_signature_t *sig,
				     const ops_public_key_t *signer)
    {
    ops_boolean_t ret;

    printf(" hash=");
    //    hashout[0]=0;
    hexdump(hash,length);

    switch(sig->key_algorithm)
	{
    case OPS_PKA_DSA:
	ret=ops_dsa_verify(hash,length,&sig->signature.dsa,&signer->key.dsa);
	break;

    case OPS_PKA_RSA:
	ret=rsa_verify(sig->hash_algorithm,hash,length,&sig->signature.rsa,
		       &signer->key.rsa);
	break;

    default:
	assert(0);
	}

    return ret;
    }

static ops_boolean_t hash_and_check_signature(ops_hash_t *hash,
					      const ops_signature_t *sig,
					      const ops_public_key_t *signer)
    {
    int n;
    unsigned char hashout[OPS_MAX_HASH];

    n=hash->finish(hash,hashout);

    return check_signature(hashout,n,sig,signer);
    }

static ops_boolean_t finalise_signature(ops_hash_t *hash,
					const ops_signature_t *sig,
					const ops_public_key_t *signer,
					const unsigned char *raw_packet)
    {
    hash_add_trailer(hash,sig,raw_packet);
    return hash_and_check_signature(hash,sig,signer);
    }

/**
 * \ingroup Verify
 *
 * Verify a certification signature.
 *
 * \param key The public key that was signed.
 * \param id The user ID that was signed.
 * \param sig The signature.
 * \param signer The public key of the signer.
 * \param raw_packet The raw signature packet.
 */
ops_boolean_t
ops_check_certification_signature(const ops_public_key_t *key,
				  const ops_user_id_t *id,
				  const ops_signature_t *sig,
				  const ops_public_key_t *signer,
				  const unsigned char *raw_packet)
    {
    ops_hash_t hash;
    size_t user_id_len=strlen((char *)id->user_id);

    init_signature(&hash,sig,key);

    if(sig->version == OPS_SIG_V4)
	{
	ops_hash_add_int(&hash,0xb4,1);
	ops_hash_add_int(&hash,user_id_len,4);
	hash.add(&hash,id->user_id,user_id_len);
	}
    else
	hash.add(&hash,id->user_id,user_id_len);

    return finalise_signature(&hash,sig,signer,raw_packet);
    }

/**
 * \ingroup Verify
 *
 * Verify a subkey signature.
 *
 * \param key The public key whose subkey was signed.
 * \param subkey The subkey of the public key that was signed.
 * \param sig The signature.
 * \param signer The public key of the signer.
 * \param raw_packet The raw signature packet.
 */
ops_boolean_t
ops_check_subkey_signature(const ops_public_key_t *key,
			   const ops_public_key_t *subkey,
			   const ops_signature_t *sig,
			   const ops_public_key_t *signer,
			   const unsigned char *raw_packet)
    {
    ops_hash_t hash;

    init_signature(&hash,sig,key);
    hash_add_key(&hash,subkey);

    return finalise_signature(&hash,sig,signer,raw_packet);
    }

/**
 * \ingroup Verify
 *
 * Verify a signature on a hash (the hash will have already been fed
 * the material that was being signed, for example signed cleartext).
 *
 * \param hash A hash structure of appropriate type that has been fed
 * the material to be signed. This MUST NOT have been finalised.
 * \param sig The signature to be verified.
 * \param signer The public key of the signer.
 */
ops_boolean_t
ops_check_hash_signature(ops_hash_t *hash,
			 const ops_signature_t *sig,
			 const ops_public_key_t *signer)
    {
    if(sig->hash_algorithm != hash->algorithm)
	return ops_false;

    return finalise_signature(hash,sig,signer,NULL);
    }
    

/**
 * \ingroup Create
 *
 * ops_signature_start() creates a V4 public key signature with a SHA1 hash.
 * 
 * \param sig The signature structure to initialise
 * \param key The public key to be signed
 * \param id The user ID being bound to the key
 * \param type Signature type
 * \todo Expand description. Allow other hashes.
 */
void ops_signature_start_key_signature(ops_create_signature_t *sig,
				       const ops_public_key_t *key,
				       const ops_user_id_t *id,
				       ops_sig_type_t type)
    {
    memset(sig,'\0',sizeof *sig);
    // XXX: refactor with check (in several ways - check should probably
    // use the buffered writer to construct packets (done), and also should
    // share code for hash calculation)
    sig->sig.version=OPS_SIG_V4;
    sig->sig.hash_algorithm=OPS_HASH_SHA1;
    sig->sig.key_algorithm=key->algorithm;
    sig->sig.type=type;

    sig->hashed_data_length=-1;

    init_signature(&sig->hash,&sig->sig,key);

    ops_hash_add_int(&sig->hash,0xb4,1);
    ops_hash_add_int(&sig->hash,strlen((char *)id->user_id),4);
    sig->hash.add(&sig->hash,id->user_id,strlen((char *)id->user_id));

    // since this has subpackets and stuff, we have to buffer the whole
    // thing to get counts before writing.
    ops_memory_init(&sig->mem,100);
    sig->info.writer=ops_writer_memory;
    sig->info.arg=&sig->mem;

    // write nearly up to the first subpacket
    ops_write_scalar(sig->sig.version,1,&sig->info);
    ops_write_scalar(sig->sig.type,1,&sig->info);
    ops_write_scalar(sig->sig.key_algorithm,1,&sig->info);
    ops_write_scalar(sig->sig.hash_algorithm,1,&sig->info);

    // dummy hashed subpacket count
    sig->hashed_count_offset=sig->mem.length;
    ops_write_scalar(0,2,&sig->info);
    }

/**
 * \ingroup Create
 *
 * Create a V4 public key signature over some plaintext.
 * 
 * \param sig The signature structure to initialise
 * \param id
 * \param type
 * \todo Expand description. Allow other hashes.
 */
void ops_signature_start_plaintext_signature(ops_create_signature_t *sig,
					     ops_hash_algorithm_t hash,
					     ops_sig_type_t type)
    {
    memset(sig,'\0',sizeof *sig);
    // XXX: refactor with check (in several ways - check should probably
    // use the buffered writer to construct packets (done), and also should
    // share code for hash calculation)
    sig->sig.version=OPS_SIG_V4;
    sig->sig.hash_algorithm=hash;
    sig->sig.type=type;

    sig->hashed_data_length=-1;

    common_init_signature(&sig->hash,&sig->sig);

    // since this has subpackets and stuff, we have to buffer the whole
    // thing to get counts before writing.
    ops_memory_init(&sig->mem,100);
    sig->info.writer=ops_writer_memory;
    sig->info.arg=&sig->mem;

    // write nearly up to the first subpacket
    ops_write_scalar(sig->sig.version,1,&sig->info);
    ops_write_scalar(sig->sig.type,1,&sig->info);
    ops_write_scalar(sig->sig.key_algorithm,1,&sig->info);
    ops_write_scalar(sig->sig.hash_algorithm,1,&sig->info);

    // dummy hashed subpacket count
    sig->hashed_count_offset=sig->mem.length;
    ops_write_scalar(0,2,&sig->info);
    }

/**
 * \ingroup Create
 *
 * Add plaintext data to a signature-to-be.
 *
 * \param sig The signature-to-be.
 * \param buf The plaintext data.
 * \param length The amount of plaintext data.
 */
void ops_signature_add_data(ops_create_signature_t *sig,const void *buf,
			    size_t length)
    {
    sig->hash.add(&sig->hash,buf,length);
    }

/**
 * \ingroup Create
 *
 * Mark the end of the hashed subpackets in the signature
 *
 * \param sig
 */

void ops_signature_hashed_subpackets_end(ops_create_signature_t *sig)
    {
    sig->hashed_data_length=sig->mem.length-sig->hashed_count_offset-2;
    ops_memory_place_int(&sig->mem,sig->hashed_count_offset,
			 sig->hashed_data_length,2);
    // dummy unhashed subpacket count
    sig->unhashed_count_offset=sig->mem.length;
    ops_write_scalar(0,2,&sig->info);
    }

/**
 * \ingroup Create
 *
 * Write out a signature
 *
 * \param sig
 * \param key
 * \param skey
 * \param info
 *
 * \todo get a better description of how/when this is used
 */

void ops_write_signature(ops_create_signature_t *sig,ops_public_key_t *key,
			 ops_secret_key_t *skey,ops_create_info_t *info)
    {
    assert(sig->hashed_data_length != (unsigned)-1);

    ops_memory_place_int(&sig->mem,sig->unhashed_count_offset,
			 sig->mem.length-sig->unhashed_count_offset-2,2);

    // add the packet from version number to end of hashed subpackets
    sig->hash.add(&sig->hash,sig->mem.buf,sig->unhashed_count_offset);
    ops_hash_add_int(&sig->hash,sig->sig.version,1);
    ops_hash_add_int(&sig->hash,0xff,1);
    ops_hash_add_int(&sig->hash,sig->hashed_data_length,4);

    // XXX: technically, we could figure out how big the signature is
    // and write it directly to the output instead of via memory.
    assert(key->algorithm == OPS_PKA_RSA);
    rsa_sign(&sig->hash,&key->key.rsa,&skey->key.rsa,&sig->info);

    ops_write_ptag(OPS_PTAG_CT_SIGNATURE,info);
    ops_write_length(sig->mem.length,info);
    ops_write(sig->mem.buf,sig->mem.length,info);

    ops_memory_release(&sig->mem);
    }

/**
 * \ingroup Create
 * 
 * ops_signature_add_creation_time() adds a creation time to the signature.
 * 
 * \param sig
 * \param when
 */
void ops_signature_add_creation_time(ops_create_signature_t *sig,time_t when)
    {
    ops_write_ss_header(5,OPS_PTAG_SS_CREATION_TIME,&sig->info);
    ops_write_scalar(when,4,&sig->info);
    }

/**
 * \ingroup Create
 *
 * Adds issuer's key ID to the signature
 *
 * \param sig
 * \param keyid
 */

void ops_signature_add_issuer_key_id(ops_create_signature_t *sig,
				     const unsigned char keyid[OPS_KEY_ID_SIZE])
    {
    ops_write_ss_header(OPS_KEY_ID_SIZE+1,OPS_PTAG_SS_ISSUER_KEY_ID,&sig->info);
    ops_write(keyid,OPS_KEY_ID_SIZE,&sig->info);
    }

/**
 * \ingroup Create
 *
 * Adds primary user ID to the signature
 *
 * \param sig
 * \param primary
 */
void ops_signature_add_primary_user_id(ops_create_signature_t *sig,
				       ops_boolean_t primary)
    {
    ops_write_ss_header(2,OPS_PTAG_SS_PRIMARY_USER_ID,&sig->info);
    ops_write_scalar(primary,1,&sig->info);
    }
