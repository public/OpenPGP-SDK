#include "memory.h"
#include <stdlib.h>
#include <assert.h>

#ifdef DMALLOC
# include <dmalloc.h>
#endif

void ops_memory_init(ops_memory_t *mem,size_t initial_size)
    {
    mem->length=0;
    if(mem->buf)
	{
	if(mem->allocated < initial_size)
	    {
	    mem->buf=realloc(mem->buf,initial_size);
	    mem->allocated=initial_size;
	    }
	return;
	}
    mem->buf=malloc(initial_size);
    mem->allocated=initial_size;
    }

void ops_memory_pad(ops_memory_t *mem,size_t length)
    {
    assert(mem->allocated >= mem->length);
    if(mem->allocated < mem->length+length)
	{
	mem->allocated=mem->allocated*2+length;
	mem->buf=realloc(mem->buf,mem->allocated);
	}
    assert(mem->allocated >= mem->length+length);
    }

void ops_memory_add(ops_memory_t *mem,const unsigned char *src,size_t length)
    {
    ops_memory_pad(mem,length);
    memcpy(mem->buf+mem->length,src,length);
    mem->length+=length;
    }

void ops_memory_add_int(ops_memory_t *mem,unsigned n,size_t length)
    {
    unsigned char c[1];

    while(length--)
	{
	c[0]=n >> (length*8);
	ops_memory_add(mem,c,1);
	}
    }

void ops_memory_add_mpi(ops_memory_t *out,const BIGNUM *bn)
    {
    unsigned length=BN_num_bits(bn);
    unsigned char buf[8192];

    assert(length <= 65535);
    BN_bn2bin(bn,buf);
    ops_memory_add_int(out,length,2);
    ops_memory_add(out,buf,(length+7)/8);
    }

void ops_memory_release(ops_memory_t *mem)
    {
    free(mem->buf);
    mem->buf=NULL;
    }
