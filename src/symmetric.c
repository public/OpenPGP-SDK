#include <openpgpsdk/crypto.h>
#include <string.h>
#include <assert.h>
#include <openssl/cast.h>
#include <openssl/idea.h>
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

static ops_reader_ret_t encrypted_data_reader(unsigned char *dest,
					      unsigned *plength,
					      ops_reader_flags_t flags,
					      ops_error_t **errors,
					      ops_reader_info_t *rinfo,
					      ops_parse_cb_info_t *cbinfo)
    {
    encrypted_arg_t *arg=ops_reader_get_arg(rinfo);
    unsigned length=*plength;

    OPS_USED(flags);

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
		   || !rinfo->pinfo->reading_v3_secret);

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
		return OPS_R_EARLY_EOF;

	    if(!arg->region->indeterminate)
		{
		n-=arg->region->length_read;
		if(n > sizeof buffer)
		    n=sizeof buffer;
		}
	    else
		n=sizeof buffer;

	    // we can only read as much as we're asked for in v3 keys
	    // because they're partially unencrypted!
	    if(rinfo->pinfo->reading_v3_secret && n > length)
		n=length;

	    if(!ops_stacked_limited_read(buffer,n,arg->region,errors,rinfo,
					 cbinfo))
		return OPS_R_EARLY_EOF;

	    if(!rinfo->pinfo->reading_v3_secret
	       || !rinfo->pinfo->reading_mpi_length)
		arg->decrypted_count=arg->decrypt->decrypt(arg->decrypt,
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

    return OPS_R_OK;
    }

void ops_reader_push_decrypt(ops_parse_info_t *pinfo,ops_decrypt_t *decrypt,
			     ops_region_t *region)
    {
    encrypted_arg_t *arg=ops_mallocz(sizeof *arg);

    arg->decrypt=decrypt;
    arg->region=region;

    arg->decrypt->init(arg->decrypt);

    ops_reader_push(pinfo,encrypted_data_reader,arg);
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

/* Only IDEA has a resync operation */
static void std_resync(ops_decrypt_t *decrypt)
    {
    OPS_USED(decrypt);

    assert(0);
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
    memcpy(decrypt->civ,decrypt->iv,decrypt->blocksize);
    decrypt->num=0;
    }

static size_t cast5_decrypt(ops_decrypt_t *decrypt,void *out,const void *in,
			    int count)
    {
    CAST_cfb64_encrypt(in,out,count,decrypt->data,decrypt->civ,&decrypt->num,
		       0);

    return count;
    }

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
    cast5_decrypt,
    std_finish,
    TRAILER
    };

static void idea_init(ops_decrypt_t *decrypt)
    {
    assert(decrypt->keysize == IDEA_KEY_LENGTH);

    free(decrypt->data);
    decrypt->data=malloc(sizeof(IDEA_KEY_SCHEDULE));

    // note that we don't invert the key for CFB mode
    idea_set_encrypt_key(decrypt->key,decrypt->data);

    memcpy(decrypt->civ,decrypt->iv,decrypt->blocksize);
    idea_ecb_encrypt(decrypt->civ,decrypt->siv,decrypt->data);

    decrypt->num=0;
    }

static void idea_resync(ops_decrypt_t *decrypt)
    {
    if(decrypt->num == 8)
	return;

    memmove(decrypt->civ+8-decrypt->num,decrypt->civ,decrypt->num);
    memcpy(decrypt->civ,decrypt->siv+decrypt->num,8-decrypt->num);
    decrypt->num=0;
    }

static size_t idea_decrypt(ops_decrypt_t *decrypt,void *out_,const void *in_,
			   int count)
    {
    unsigned char *out=out_;
    const unsigned char *in=in_;
    int saved=count;

    /* in order to support v3's weird resyncing we have to implement CFB mode
       ourselves */
    while(count-- > 0)
	{
	unsigned char t;

	if(decrypt->num == 8)
	    {
	    memcpy(decrypt->siv,decrypt->civ,sizeof decrypt->siv);
	    idea_ecb_encrypt(decrypt->civ,decrypt->civ,decrypt->data);
	    decrypt->num=0;
	    }
	t=decrypt->civ[decrypt->num];
	*out++=t^(decrypt->civ[decrypt->num++]=*in++);
	}

    return saved;
    }

static ops_decrypt_t idea=
    {
    OPS_SA_IDEA,
    IDEA_BLOCK,
    IDEA_KEY_LENGTH,
    std_set_iv,
    std_set_key,
    idea_init,
    idea_resync,
    idea_decrypt,
    std_finish,
    TRAILER
    };

static ops_decrypt_t *get_proto(ops_symmetric_algorithm_t alg)
    {
    switch(alg)
	{
    case OPS_SA_CAST5:
	return &cast5;

    case OPS_SA_IDEA:
	return &idea;

    default:
	assert(0);
	}

    return NULL;
    }

void ops_decrypt_any(ops_decrypt_t *decrypt,ops_symmetric_algorithm_t alg)
    { *decrypt=*get_proto(alg); }

unsigned ops_block_size(ops_symmetric_algorithm_t alg)
    {
    ops_decrypt_t *p=get_proto(alg);

    if(!p)
	return 0;

    return p->blocksize;
    }

unsigned ops_key_size(ops_symmetric_algorithm_t alg)
    {
    ops_decrypt_t *p=get_proto(alg);

    if(!p)
	return 0;

    return p->keysize;
    }
