/** \file
 */

#include <openpgpsdk/crypto.h>
#include <assert.h>

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

