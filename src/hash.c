/** \file
 */

#include <openpgpsdk/crypto.h>
#include <assert.h>
#include <string.h>

void ops_hash_add_int(ops_hash_t *hash,unsigned n,unsigned length)
    {
    while(length--)
	{
	unsigned char c[1];

	c[0]=n >> (length*8);
	hash->add(hash,c,1);
	}
    }

void ops_hash_any(ops_hash_t *hash,ops_hash_algorithm_t alg)
    {
    switch(alg)
	{
    case OPS_HASH_MD5:
	ops_hash_md5(hash);
	break;

    case OPS_HASH_SHA1:
	ops_hash_sha1(hash);
	break;

    default:
	assert(0);
	}
    }

unsigned ops_hash_size(ops_hash_algorithm_t alg)
    {
    switch(alg)
	{
    case OPS_HASH_MD5:
	return 16;

    case OPS_HASH_SHA1:
	return 20;

    default:
	assert(0);
	}

    return 0;
    }

ops_hash_algorithm_t ops_hash_algorithm_from_text(const char *hash)
    {
    if(!strcmp(hash,"SHA1"))
	return OPS_HASH_SHA1;
    else if(!strcmp(hash,"MD5"))
	return OPS_HASH_MD5;

    return OPS_HASH_UNKNOWN;
    }

unsigned ops_hash(unsigned char *out,ops_hash_algorithm_t alg,const void *in,
		  size_t length)
    {
    ops_hash_t hash;

    ops_hash_any(&hash,alg);
    hash.init(&hash);
    hash.add(&hash,in,length);
    return hash.finish(&hash,out);
    }

static ops_reader_ret_t hash_reader(unsigned char *dest,
				    unsigned *plength,
				    ops_reader_flags_t flags,
				    ops_error_t **errors,
				    ops_reader_info_t *rinfo,
				    ops_parse_cb_info_t *cbinfo)
    {
    ops_hash_t *hash=ops_reader_get_arg(rinfo);
    ops_reader_ret_t ret=ops_stacked_read(dest,plength,flags,errors,rinfo,
					  cbinfo);

    hash->add(hash,dest,*plength);

    return ret;
    }

void ops_reader_push_hash(ops_parse_info_t *pinfo,ops_hash_t *hash)
    {
    hash->init(hash);
    ops_reader_push(pinfo,hash_reader,hash);
    }

void ops_reader_pop_hash(ops_parse_info_t *pinfo)
    { ops_reader_pop(pinfo); }
