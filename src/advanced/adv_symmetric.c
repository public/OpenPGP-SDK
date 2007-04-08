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

#include <openpgpsdk/final.h>

typedef struct
    {
    unsigned char decrypted[1024];
    size_t decrypted_count;
    size_t decrypted_offset;
    ops_decrypt_t *decrypt;
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
	arg->decrypt->resync(arg->decrypt);
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
	    dest+=n;
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
		arg->decrypted_count=ops_decrypt_decrypt(arg->decrypt,
							 arg->decrypted,
							 buffer,n);
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

void ops_reader_push_decrypt(ops_parse_info_t *pinfo,ops_decrypt_t *decrypt,
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

    arg->decrypt->finish(arg->decrypt);
    free(arg);
    
    ops_reader_pop(pinfo);
    }

static void std_set_iv(ops_decrypt_t *decrypt,const unsigned char *iv)
    { memcpy(decrypt->iv,iv,decrypt->blocksize); }

static void std_set_key(ops_decrypt_t *decrypt,const unsigned char *key)
    { memcpy(decrypt->key,key,decrypt->keysize); }

static void std_resync(ops_decrypt_t *decrypt)
    {
    if(decrypt->num == decrypt->blocksize)
	return;

    memmove(decrypt->civ+decrypt->blocksize-decrypt->num,decrypt->civ,
	    decrypt->num);
    memcpy(decrypt->civ,decrypt->siv+decrypt->num,
	   decrypt->blocksize-decrypt->num);
    decrypt->num=0;
    }

static void std_finish(ops_decrypt_t *decrypt)
    {
    free(decrypt->data);
    decrypt->data=NULL;
    }

static void cast5_init(ops_decrypt_t *decrypt)
    {
    free(decrypt->data);
    decrypt->data=malloc(sizeof(CAST_KEY));
    CAST_set_key(decrypt->data,decrypt->keysize,decrypt->key);
    }

static void cast5_encrypt(ops_decrypt_t *decrypt,void *out,const void *in)
    { CAST_ecb_encrypt(in,out,decrypt->data,1); }

#define TRAILER		"","","","",0,NULL

static ops_decrypt_t cast5=
    {
    OPS_SA_CAST5,
    CAST_BLOCK,
    CAST_KEY_LENGTH,
    std_set_iv,
    std_set_key,
    cast5_init,
    std_resync,
    cast5_encrypt,
    std_finish,
    TRAILER
    };

#ifndef OPENSSL_NO_IDEA
static void idea_init(ops_decrypt_t *decrypt)
    {
    assert(decrypt->keysize == IDEA_KEY_LENGTH);

    free(decrypt->data);
    decrypt->data=malloc(sizeof(IDEA_KEY_SCHEDULE));

    // note that we don't invert the key for CFB mode
    idea_set_encrypt_key(decrypt->key,decrypt->data);
    }

static void idea_block_encrypt(ops_decrypt_t *decrypt,void *out,const void *in)
    { idea_ecb_encrypt(in,out,decrypt->data); }

static const ops_decrypt_t idea=
    {
    OPS_SA_IDEA,
    IDEA_BLOCK,
    IDEA_KEY_LENGTH,
    std_set_iv,
    std_set_key,
    idea_init,
    std_resync,
    idea_block_encrypt,
    std_finish,
    TRAILER
    };
#endif /* OPENSSL_NO_IDEA */

static void aes256_init(ops_decrypt_t *decrypt)
    {
    free(decrypt->data);
    decrypt->data=malloc(sizeof(AES_KEY));
    AES_set_encrypt_key(decrypt->key,256,decrypt->data);
    }

static void aes_block_encrypt(ops_decrypt_t *decrypt,void *out,const void *in)
    { AES_encrypt(in,out,decrypt->data); }

static const ops_decrypt_t aes256=
    {
    OPS_SA_AES_256,
    AES_BLOCK_SIZE,
    256/8,
    std_set_iv,
    std_set_key,
    aes256_init,
    std_resync,
    aes_block_encrypt,
    std_finish,
    TRAILER
    };

static void tripledes_init(ops_decrypt_t *decrypt)
    {
    DES_key_schedule *keys;
    int n;

    free(decrypt->data);
    keys=decrypt->data=malloc(3*sizeof(DES_key_schedule));

    for(n=0 ; n < 3 ; ++n)
	DES_set_key((DES_cblock *)(decrypt->key+n*8),&keys[n]);
    }

static void tripledes_block_encrypt(ops_decrypt_t *decrypt,void *out,
				    const void *in)
    {
    DES_key_schedule *keys=decrypt->data;

    DES_ecb3_encrypt((void *)in,out,&keys[0],&keys[1],&keys[2],1);
    }

static const ops_decrypt_t tripledes=
    {
    OPS_SA_TRIPLEDES,
    8,
    24,
    std_set_iv,
    std_set_key,
    tripledes_init,
    std_resync,
    tripledes_block_encrypt,
    std_finish,
    TRAILER
    };

static const ops_decrypt_t *get_proto(ops_symmetric_algorithm_t alg)
    {
    switch(alg)
	{
    case OPS_SA_CAST5:
	return &cast5;

#ifndef OPENSSL_NO_IDEA
    case OPS_SA_IDEA:
	return &idea;
#endif /* OPENSSL_NO_IDEA */

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

void ops_decrypt_any(ops_decrypt_t *decrypt,ops_symmetric_algorithm_t alg)
    { *decrypt=*get_proto(alg); }

unsigned ops_block_size(ops_symmetric_algorithm_t alg)
    {
    const ops_decrypt_t *p=get_proto(alg);

    if(!p)
	return 0;

    return p->blocksize;
    }

unsigned ops_key_size(ops_symmetric_algorithm_t alg)
    {
    const ops_decrypt_t *p=get_proto(alg);

    if(!p)
	return 0;

    return p->keysize;
    }

void ops_decrypt_init(ops_decrypt_t *decrypt)
    {
    decrypt->base_init(decrypt);
    decrypt->block_encrypt(decrypt,decrypt->siv,decrypt->iv);
    memcpy(decrypt->civ,decrypt->siv,decrypt->blocksize);
    decrypt->num=0;
    }

size_t ops_decrypt_decrypt(ops_decrypt_t *decrypt,void *out_,const void *in_,
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
	    decrypt->block_encrypt(decrypt,decrypt->civ,decrypt->civ);
	    decrypt->num=0;
	    }
	t=decrypt->civ[decrypt->num];
	*out++=t^(decrypt->civ[decrypt->num++]=*in++);
	}

    return saved;
    }
