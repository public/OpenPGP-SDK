#include "hash.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <assert.h>
#include <stdlib.h>

static void md5_init(ops_hash_t *hash)
    {
    assert(!hash->data);
    hash->data=malloc(sizeof(MD5_CTX));
    MD5_Init(hash->data);
    }

static void md5_add(ops_hash_t *hash,const unsigned char *data,unsigned length)
    {
    MD5_Update(hash->data,data,length);
    }

static unsigned md5_finish(ops_hash_t *hash,unsigned char *out)
    {
    MD5_Final(out,hash->data);
    free(hash->data);
    hash->data=NULL;
    return 16;
    }

static ops_hash_t md5={md5_init,md5_add,md5_finish};

void ops_hash_md5(ops_hash_t *hash)
    {
    *hash=md5;
    }

static void sha1_init(ops_hash_t *hash)
    {
    assert(!hash->data);
    hash->data=malloc(sizeof(SHA_CTX));
    SHA1_Init(hash->data);
    }

static void sha1_add(ops_hash_t *hash,const unsigned char *data,
		     unsigned length)
    {
    SHA1_Update(hash->data,data,length);
    }

static unsigned sha1_finish(ops_hash_t *hash,unsigned char *out)
    {
    SHA1_Final(out,hash->data);
    free(hash->data);
    hash->data=NULL;
    return 20;
    }

static ops_hash_t sha1={sha1_init,sha1_add,sha1_finish};

void ops_hash_sha1(ops_hash_t *hash)
    {
    *hash=sha1;
    }
