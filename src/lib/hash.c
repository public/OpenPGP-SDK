/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. 
 * 
 * You may obtain a copy of the License at 
 *     http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** \file
 */

#include <openpgpsdk/crypto.h>
#include <assert.h>
#include <string.h>

#include <openpgpsdk/final.h>

static int debug=0;

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

void ops_calc_mdc_hash(const unsigned char* preamble, const size_t sz_preamble, const unsigned char* plaintext, const unsigned int sz_plaintext, unsigned char *hashed)
    {
    ops_hash_t hash;
    unsigned char c[1];

    if (debug)
        {
        unsigned int i=0;
        fprintf(stderr,"ops_calc_mdc_hash():\n");

        fprintf(stderr,"\npreamble: ");
        for (i=0; i<sz_preamble;i++)
            fprintf(stderr," 0x%02x", preamble[i]);
        fprintf(stderr,"\n");

        fprintf(stderr,"\nplaintext (len=%d): ",sz_plaintext);
        for (i=0; i<sz_plaintext;i++)
            fprintf(stderr," 0x%02x", plaintext[i]);
        fprintf(stderr,"\n");
        }

    // init
    ops_hash_any(&hash, OPS_HASH_SHA1);
    hash.init(&hash);

    // preamble
    hash.add(&hash,preamble,sz_preamble);
    // plaintext
    hash.add(&hash,plaintext,sz_plaintext); 
    // MDC packet tag
    c[0]=0xD3;
    hash.add(&hash,&c[0],1);   
    // MDC packet len
    c[0]=0x14;
    hash.add(&hash,&c[0],1);   

    //finish
    hash.finish(&hash,hashed);

    if (debug)
        {
        unsigned int i=0;
        fprintf(stderr,"\nhashed (len=%d): ",SHA_DIGEST_LENGTH);
        for (i=0; i<SHA_DIGEST_LENGTH;i++)
            fprintf(stderr," 0x%02x", hashed[i]);
        fprintf(stderr,"\n");
        }
    }

ops_boolean_t ops_is_hash_alg_supported(const ops_hash_algorithm_t *hash_alg)
    {
    switch (*hash_alg)
        {
    case OPS_HASH_MD5:
    case OPS_HASH_SHA1:
        return ops_true;

    default:
        return ops_false;
        }
    }

// EOF
