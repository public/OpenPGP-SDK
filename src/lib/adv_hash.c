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

static int hash_reader(void *dest,size_t length,ops_error_t **errors,
		       ops_reader_info_t *rinfo,ops_parse_cb_info_t *cbinfo)
    {
    ops_hash_t *hash=ops_reader_get_arg(rinfo);
    int r=ops_stacked_read(dest,length,errors,rinfo,cbinfo);

    if(r <= 0)
	return r;
	
    hash->add(hash,dest,r);

    return r;
    }

void ops_reader_push_hash(ops_parse_info_t *pinfo,ops_hash_t *hash)
    {
    hash->init(hash);
    ops_reader_push(pinfo,hash_reader,NULL,hash);
    }

void ops_reader_pop_hash(ops_parse_info_t *pinfo)
    { ops_reader_pop(pinfo); }
