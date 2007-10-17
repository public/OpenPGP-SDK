#include <openpgpsdk/crypto.h>
#include <string.h>
#include <assert.h>
#include <openssl/cast.h>
#ifndef OPENSSL_NO_IDEA
#include <openssl/idea.h>
#endif
#include <openssl/aes.h>
#include <openssl/des.h>
#include "parse_local.h"

#include <openpgpsdk/packet-show.h>
#include <openpgpsdk/final.h>

#ifndef ATTRIBUTE_UNUSED

#ifndef WIN32
#define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
#else
#define ATTRIBUTE_UNUSED 
#endif // #ifndef WIN32

#endif /* ATTRIBUTE_UNUSED */


// \todo there's also a encrypted_arg_t in adv_create.c 
// which is used for *encrypting* whereas this is used
// for *decrypting*

typedef struct
    {
    unsigned char decrypted[1024];
    size_t decrypted_count;
    size_t decrypted_offset;
    ops_crypt_t *decrypt;
    ops_region_t *region;
    ops_boolean_t prev_read_was_plain:1;
    } encrypted_arg_t;

static int encrypted_data_reader(void *dest,size_t length,ops_error_t **errors,
				 ops_reader_info_t *rinfo,
				 ops_parse_cb_info_t *cbinfo)
    {
    encrypted_arg_t *arg=ops_reader_get_arg(rinfo);
    int saved=length;

    // V3 MPIs have the count plain and the cipher is reset after each count
    if(arg->prev_read_was_plain && !rinfo->pinfo->reading_mpi_length)
	{
	assert(rinfo->pinfo->reading_v3_secret);
	arg->decrypt->decrypt_resync(arg->decrypt);
	arg->prev_read_was_plain=ops_false;
	}
    else if(rinfo->pinfo->reading_v3_secret
	    && rinfo->pinfo->reading_mpi_length)
	arg->prev_read_was_plain=ops_true;

    while(length > 0)
	{
	if(arg->decrypted_count)
	    {
	    unsigned n;

	    // if we are reading v3 we should never read more than
	    // we're asked for
	    assert(length >= arg->decrypted_count
		   || (!rinfo->pinfo->reading_v3_secret
		       && !rinfo->pinfo->exact_read));

	    if(length > arg->decrypted_count)
		n=arg->decrypted_count;
	    else
		n=length;

	    memcpy(dest,arg->decrypted+arg->decrypted_offset,n);
	    arg->decrypted_count-=n;
	    arg->decrypted_offset+=n;
	    length-=n;
#ifdef WIN32
	    (char*)dest+=n;
#else
        dest+=n;
#endif
	    }
	else
	    {
	    unsigned n=arg->region->length;
	    unsigned char buffer[1024];

	    if(!n)
		return -1;

	    if(!arg->region->indeterminate)
		{
		n-=arg->region->length_read;
		if(n == 0)
		    return saved-length;
		if(n > sizeof buffer)
		    n=sizeof buffer;
		}
	    else
		n=sizeof buffer;

	    // we can only read as much as we're asked for in v3 keys
	    // because they're partially unencrypted!
	    if((rinfo->pinfo->reading_v3_secret || rinfo->pinfo->exact_read)
	       && n > length)
		n=length;

	    if(!ops_stacked_limited_read(buffer,n,arg->region,errors,rinfo,
					 cbinfo))
		return -1;

	    if(!rinfo->pinfo->reading_v3_secret
	       || !rinfo->pinfo->reading_mpi_length)
                {
                arg->decrypted_count=ops_decrypt_se_ip(arg->decrypt,
                                  arg->decrypted,
                                  buffer,n);

                /*
        fprintf(stderr,"READING:\nencrypted: ");
        int i=0;
        for (i=0; i<16; i++)
            fprintf(stderr,"%2x ", buffer[i]);
        fprintf(stderr,"\n");
        fprintf(stderr,"decrypted:   ");
        for (i=0; i<16; i++)
            fprintf(stderr,"%2x ", arg->decrypted[i]);
        fprintf(stderr,"\n");
                */
                }
	    else
		{
		memcpy(arg->decrypted,buffer,n);
		arg->decrypted_count=n;
		}

	    assert(arg->decrypted_count > 0);

	    arg->decrypted_offset=0;
	    }
	}

    return saved;
    }

static void encrypted_data_destroyer(ops_reader_info_t *rinfo)
    { free(ops_reader_get_arg(rinfo)); }

void ops_reader_push_decrypt(ops_parse_info_t *pinfo,ops_crypt_t *decrypt,
			     ops_region_t *region)
    {
    encrypted_arg_t *arg=ops_mallocz(sizeof *arg);

    arg->decrypt=decrypt;
    arg->region=region;

    ops_decrypt_init(arg->decrypt);

    ops_reader_push(pinfo,encrypted_data_reader,encrypted_data_destroyer,arg);
    }

void ops_reader_pop_decrypt(ops_parse_info_t *pinfo)
    {
    encrypted_arg_t *arg=ops_reader_get_arg(ops_parse_get_rinfo(pinfo));

    arg->decrypt->decrypt_finish(arg->decrypt);
    free(arg);
    
    ops_reader_pop(pinfo);
    }

static void std_set_iv(ops_crypt_t *crypt,const unsigned char *iv)
    { 
    memcpy(crypt->iv,iv,crypt->blocksize); 
    crypt->num=0;
    }

static void std_set_key(ops_crypt_t *crypt,const unsigned char *key)
    { memcpy(crypt->key,key,crypt->keysize); }

static void std_resync(ops_crypt_t *decrypt)
    {
    if(decrypt->num == decrypt->blocksize)
	return;

    memmove(decrypt->civ+decrypt->blocksize-decrypt->num,decrypt->civ,
	    decrypt->num);
    memcpy(decrypt->civ,decrypt->siv+decrypt->num,
	   decrypt->blocksize-decrypt->num);
    decrypt->num=0;
    }

static void std_finish(ops_crypt_t *crypt)
    {
    if (crypt->encrypt_key)
        {
        free(crypt->encrypt_key);
        crypt->encrypt_key=NULL;
        }
    if (crypt->decrypt_key)
        {
        free(crypt->decrypt_key);
        crypt->decrypt_key=NULL;
        }
    }

static void cast5_init(ops_crypt_t *crypt)
    {
    if (crypt->encrypt_key)
        free(crypt->encrypt_key);
    crypt->encrypt_key=malloc(sizeof(CAST_KEY));
    CAST_set_key(crypt->encrypt_key,crypt->keysize,crypt->key);
    crypt->decrypt_key=malloc(sizeof(CAST_KEY));
    CAST_set_key(crypt->decrypt_key,crypt->keysize,crypt->key);
    }

static void cast5_block_encrypt(ops_crypt_t *crypt,void *out,const void *in)
    { CAST_ecb_encrypt(in,out,crypt->encrypt_key,CAST_ENCRYPT); }

static void cast5_block_decrypt(ops_crypt_t *crypt,void *out,const void *in)
    { CAST_ecb_encrypt(in,out,crypt->encrypt_key,CAST_DECRYPT); }

static void cast5_cfb_encrypt(ops_crypt_t *crypt,void *out,const void *in, size_t count)
    { 
    CAST_cfb64_encrypt(in,out,count,
                       crypt->encrypt_key, crypt->iv, (int *)&crypt->num,
                       CAST_ENCRYPT); 
    }

static void cast5_cfb_decrypt(ops_crypt_t *crypt,void *out,const void *in, size_t count)
    { 
    CAST_cfb64_encrypt(in,out,count,
                       crypt->encrypt_key, crypt->iv, (int *)&crypt->num,
                       CAST_DECRYPT); 
    }

#define TRAILER		"","","","",0,NULL,NULL

static ops_crypt_t cast5=
    {
    OPS_SA_CAST5,
    CAST_BLOCK,
    CAST_KEY_LENGTH,
    std_set_iv,
    std_set_key,
    cast5_init,
    std_resync,
    cast5_block_encrypt,
    cast5_block_decrypt,
    cast5_cfb_encrypt,
    cast5_cfb_decrypt,
    std_finish,
    TRAILER
    };

#ifndef OPENSSL_NO_IDEA
static void idea_init(ops_crypt_t *crypt)
    {
    assert(crypt->keysize == IDEA_KEY_LENGTH);

    if (crypt->encrypt_key)
        free(crypt->encrypt_key);
    crypt->encrypt_key=malloc(sizeof(IDEA_KEY_SCHEDULE));

    // note that we don't invert the key when decrypting for CFB mode
    idea_set_encrypt_key(crypt->key,crypt->encrypt_key);

    if (crypt->decrypt_key)
        free(crypt->decrypt_key);
    crypt->decrypt_key=malloc(sizeof(IDEA_KEY_SCHEDULE));

    idea_set_decrypt_key(crypt->encrypt_key,crypt->decrypt_key);
    }

static void idea_block_encrypt(ops_crypt_t *crypt,void *out,const void *in)
    { idea_ecb_encrypt(in,out,crypt->encrypt_key); }

static void idea_block_decrypt(ops_crypt_t *crypt,void *out,const void *in)
    { idea_ecb_encrypt(in,out,crypt->decrypt_key); }

static void idea_cfb_encrypt(ops_crypt_t *crypt,void *out,const void *in, size_t count)
    { 
    idea_cfb64_encrypt(in,out,count,
                       crypt->encrypt_key, crypt->iv, (int *)&crypt->num,
                       CAST_ENCRYPT); 
    }

static void idea_cfb_decrypt(ops_crypt_t *crypt,void *out,const void *in, size_t count)
    { 
    idea_cfb64_encrypt(in,out,count,
                       crypt->decrypt_key, crypt->iv, (int *)&crypt->num,
                       CAST_DECRYPT); 
    }

static const ops_crypt_t idea=
    {
    OPS_SA_IDEA,
    IDEA_BLOCK,
    IDEA_KEY_LENGTH,
    std_set_iv,
    std_set_key,
    idea_init,
    std_resync,
    idea_block_encrypt,
    idea_block_decrypt,
    idea_cfb_encrypt,
    idea_cfb_decrypt,
    std_finish,
    TRAILER
    };
#endif /* OPENSSL_NO_IDEA */

// AES with 128-bit key (AES)

#define KEYBITS_AES128 128

static void aes128_init(ops_crypt_t *crypt)
    {
    if (crypt->encrypt_key)
        free(crypt->encrypt_key);
    crypt->encrypt_key=malloc(sizeof(AES_KEY));
    if (AES_set_encrypt_key(crypt->key,KEYBITS_AES128,crypt->encrypt_key))
        fprintf(stderr,"aes128_init: Error setting encrypt_key\n");

    if (crypt->decrypt_key)
        free(crypt->decrypt_key);
    crypt->decrypt_key=malloc(sizeof(AES_KEY));
    if (AES_set_decrypt_key(crypt->key,KEYBITS_AES128,crypt->decrypt_key))
        fprintf(stderr,"aes128_init: Error setting decrypt_key\n");
    }

static void aes_block_encrypt(ops_crypt_t *crypt,void *out,const void *in)
    { AES_encrypt(in,out,crypt->encrypt_key); }

static void aes_block_decrypt(ops_crypt_t *crypt,void *out,const void *in)
    { AES_decrypt(in,out,crypt->decrypt_key); }

static void aes_cfb_encrypt(ops_crypt_t *crypt,void *out,const void *in, size_t count)
    { 
    AES_cfb128_encrypt(in,out,count,
                       crypt->encrypt_key, crypt->iv, (int *)&crypt->num,
                       AES_ENCRYPT); 
    }

static void aes_cfb_decrypt(ops_crypt_t *crypt,void *out,const void *in, size_t count)
    { 
    AES_cfb128_encrypt(in,out,count,
                       crypt->encrypt_key, crypt->iv, (int *)&crypt->num,
                       AES_DECRYPT); 
    }

static const ops_crypt_t aes128=
    {
    OPS_SA_AES_128,
    AES_BLOCK_SIZE,
    KEYBITS_AES128/8,
    std_set_iv,
    std_set_key,
    aes128_init,
    std_resync,
    aes_block_encrypt,
    aes_block_decrypt,
    aes_cfb_encrypt,
    aes_cfb_decrypt,
    std_finish,
    TRAILER
    };

// AES with 256-bit key

#define KEYBITS_AES256 256

static void aes256_init(ops_crypt_t *crypt)
    {
    if (crypt->encrypt_key)
        free(crypt->encrypt_key);
    crypt->encrypt_key=malloc(sizeof(AES_KEY));
    if (AES_set_encrypt_key(crypt->key,KEYBITS_AES256,crypt->encrypt_key))
        fprintf(stderr,"aes256_init: Error setting encrypt_key\n");

    if (crypt->decrypt_key)
        free(crypt->decrypt_key);
    crypt->decrypt_key=malloc(sizeof(AES_KEY));
    if (AES_set_decrypt_key(crypt->key,KEYBITS_AES256,crypt->decrypt_key))
        fprintf(stderr,"aes256_init: Error setting decrypt_key\n");
    }

static const ops_crypt_t aes256=
    {
    OPS_SA_AES_256,
    AES_BLOCK_SIZE,
    KEYBITS_AES256/8,
    std_set_iv,
    std_set_key,
    aes256_init,
    std_resync,
    aes_block_encrypt,
    aes_block_decrypt,
    aes_cfb_encrypt,
    aes_cfb_decrypt,
    std_finish,
    TRAILER
    };

// Triple DES

static void tripledes_init(ops_crypt_t *crypt)
    {
    DES_key_schedule *keys;
    int n;

    if (crypt->encrypt_key)
        free(crypt->encrypt_key);
    keys=crypt->encrypt_key=malloc(3*sizeof(DES_key_schedule));

    for(n=0 ; n < 3 ; ++n)
	DES_set_key((DES_cblock *)(crypt->key+n*8),&keys[n]);
    }

static void tripledes_block_encrypt(ops_crypt_t *crypt,void *out,
				    const void *in)
    {
    DES_key_schedule *keys=crypt->encrypt_key;

    DES_ecb3_encrypt((void *)in,out,&keys[0],&keys[1],&keys[2],DES_ENCRYPT);
    }

static void tripledes_block_decrypt(ops_crypt_t *crypt,void *out,
				    const void *in)
    {
    DES_key_schedule *keys=crypt->encrypt_key;

    DES_ecb3_encrypt((void *)in,out,&keys[0],&keys[1],&keys[2],DES_DECRYPT);
    }

static void tripledes_cfb_encrypt(ops_crypt_t *crypt ATTRIBUTE_UNUSED,void *out ATTRIBUTE_UNUSED,const void *in ATTRIBUTE_UNUSED, size_t count ATTRIBUTE_UNUSED)
    { 
    assert(0);
    /*
    CAST_cfb64_encrypt(in,out,count,
                       crypt->encrypt_key, crypt->iv, (int *)&crypt->num,
                       CAST_ENCRYPT); 
    */
    }

static void tripledes_cfb_decrypt(ops_crypt_t *crypt ATTRIBUTE_UNUSED,void *out ATTRIBUTE_UNUSED,const void *in ATTRIBUTE_UNUSED, size_t count ATTRIBUTE_UNUSED)
    { 
    assert(0);
    /*
    CAST_cfb64_encrypt(in,out,count,
                       crypt->encrypt_key, crypt->iv, (int *)&crypt->num,
                       CAST_DECRYPT); 
    */
    }

static const ops_crypt_t tripledes=
    {
    OPS_SA_TRIPLEDES,
    8,
    24,
    std_set_iv,
    std_set_key,
    tripledes_init,
    std_resync,
    tripledes_block_encrypt,
    tripledes_block_decrypt,
    tripledes_cfb_encrypt,
    tripledes_cfb_decrypt,
    std_finish,
    TRAILER
    };

static const ops_crypt_t *get_proto(ops_symmetric_algorithm_t alg)
    {
    switch(alg)
	{
    case OPS_SA_CAST5:
	return &cast5;

#ifndef OPENSSL_NO_IDEA
    case OPS_SA_IDEA:
	return &idea;
#endif /* OPENSSL_NO_IDEA */

    case OPS_SA_AES_128:
	return &aes128;

    case OPS_SA_AES_256:
	return &aes256;

    case OPS_SA_TRIPLEDES:
	return &tripledes;

    default:
	// XXX: remove these
	fprintf(stderr,"Unknown algorithm: %d\n",alg);
	assert(0);
	}

    return NULL;
    }

void ops_crypt_any(ops_crypt_t *crypt,ops_symmetric_algorithm_t alg)
    { *crypt=*get_proto(alg); }

unsigned ops_block_size(ops_symmetric_algorithm_t alg)
    {
    const ops_crypt_t *p=get_proto(alg);

    if(!p)
	return 0;

    return p->blocksize;
    }

unsigned ops_key_size(ops_symmetric_algorithm_t alg)
    {
    const ops_crypt_t *p=get_proto(alg);

    if(!p)
	return 0;

    return p->keysize;
    }

void ops_encrypt_init(ops_crypt_t * encrypt)
    {
    // \todo should there be a separate ops_encrypt_init?
    ops_decrypt_init(encrypt);
    }

void ops_decrypt_init(ops_crypt_t *decrypt)
    {
    decrypt->base_init(decrypt);
    decrypt->block_encrypt(decrypt,decrypt->siv,decrypt->iv);
    memcpy(decrypt->civ,decrypt->siv,decrypt->blocksize);
    decrypt->num=0;
    }

size_t ops_decrypt_se
(ops_crypt_t *decrypt,void *out_,const void *in_,
		   size_t count)
    {
    unsigned char *out=out_;
    const unsigned char *in=in_;
    int saved=count;

    /* in order to support v3's weird resyncing we have to implement CFB mode
       ourselves */
    while(count-- > 0)
	{
	unsigned char t;

	if(decrypt->num == decrypt->blocksize)
	    {
	    memcpy(decrypt->siv,decrypt->civ,decrypt->blocksize);
	    decrypt->block_decrypt(decrypt,decrypt->civ,decrypt->civ);
	    decrypt->num=0;
	    }
	t=decrypt->civ[decrypt->num];
	*out++=t^(decrypt->civ[decrypt->num++]=*in++);
	}

    return saved;
    }

size_t ops_encrypt_se(ops_crypt_t *encrypt,void *out_,const void *in_,
		   size_t count)
    {
    unsigned char *out=out_;
    const unsigned char *in=in_;
    int saved=count;

    /* in order to support v3's weird resyncing we have to implement CFB mode
       ourselves */
    while(count-- > 0)
	{
	if(encrypt->num == encrypt->blocksize)
	    {
	    memcpy(encrypt->siv,encrypt->civ,encrypt->blocksize);
	    encrypt->block_encrypt(encrypt,encrypt->civ,encrypt->civ);
	    encrypt->num=0;
	    }
	encrypt->civ[encrypt->num]=*out++=encrypt->civ[encrypt->num]^*in++;
	++encrypt->num;
	}

    return saved;
    }

ops_boolean_t ops_is_sa_supported(ops_symmetric_algorithm_t alg)
    {
    switch (alg)
        {
    case OPS_SA_AES_128:
    case OPS_SA_AES_256:
    case OPS_SA_CAST5:
    case OPS_SA_TRIPLEDES:
#ifndef OPENSSL_NO_IDEA
    case OPS_SA_IDEA:
#endif
        return ops_true;
        break;

    default:
        fprintf(stderr,"\nWarning: %s not supported\n",
                ops_show_symmetric_algorithm(alg));
        return ops_false;
        }
    }

size_t ops_encrypt_se_ip(ops_crypt_t *crypt,void *out_,const void *in_,
                       size_t count)
    {
    if (!ops_is_sa_supported(crypt->algorithm))
        return -1;

    crypt->cfb_encrypt(crypt, out_, in_, count);

    // \todo test this number was encrypted
    return count;
    }

size_t ops_decrypt_se_ip(ops_crypt_t *crypt,void *out_,const void *in_,
                       size_t count)
    {
    if (!ops_is_sa_supported(crypt->algorithm))
        return -1;

    crypt->cfb_decrypt(crypt, out_, in_, count);

    // \todo check this number was in fact decrypted
    return count;
    }
