/** \file
 */

#include "packet.h"
#include "util.h"
#include "build.h"
#include <stdlib.h>
#include <openssl/bn.h>
#include <assert.h>
#include <string.h>

void ops_memory_make_packet(ops_memory_t *out,ops_content_tag_t tag)
    {
    size_t extra;

    if(out->length < 192)
	extra=1;
    else if(out->length < 8384)
	extra=2;
    else
	extra=5;

    ops_memory_pad(out,extra+1);
    memmove(out->buf+extra+1,out->buf,out->length);

    out->buf[0]=OPS_PTAG_ALWAYS_SET|OPS_PTAG_NEW_FORMAT|tag;

    if(out->length < 192)
	out->buf[1]=out->length;
    else if(out->length < 8384)
	{
	out->buf[1]=((out->length-192) >> 8)+192;
	out->buf[2]=out->length-192;
	}
    else
	{
	out->buf[1]=0xff;
	out->buf[2]=out->length >> 24;
	out->buf[3]=out->length >> 16;
	out->buf[4]=out->length >> 8;
	out->buf[5]=out->length;
	}

    out->length+=extra+1;
    }

void ops_build_public_key(ops_memory_t *out,const ops_public_key_t *key,
			  ops_boolean_t make_packet)
    {
    ops_memory_init(out,128);
    ops_memory_add_int(out,key->version,1);
    ops_memory_add_int(out,key->creation_time,4);
    if(key->version != 4)
	ops_memory_add_int(out,key->days_valid,2);
    ops_memory_add_int(out,key->algorithm,1);

    switch(key->algorithm)
	{
    case OPS_PKA_DSA:
	ops_memory_add_mpi(out,key->key.dsa.p);
	ops_memory_add_mpi(out,key->key.dsa.q);
	ops_memory_add_mpi(out,key->key.dsa.g);
	ops_memory_add_mpi(out,key->key.dsa.y);
	break;

    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:
	ops_memory_add_mpi(out,key->key.rsa.n);
	ops_memory_add_mpi(out,key->key.rsa.e);
	break;

    case OPS_PKA_ELGAMAL:
	ops_memory_add_mpi(out,key->key.elgamal.p);
	ops_memory_add_mpi(out,key->key.elgamal.g);
	ops_memory_add_mpi(out,key->key.elgamal.y);
	break;
	}

    if(make_packet)
	ops_memory_make_packet(out,OPS_PTAG_CT_PUBLIC_KEY);
    }
