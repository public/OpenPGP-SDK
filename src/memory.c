/** \file
 */

#include "memory.h"
#include "create.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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

// XXX: this could be refactored via the writer, but an awful lot of
// hoops to jump through for 2 lines of code!
void ops_memory_place_int(ops_memory_t *mem,unsigned offset,unsigned n,
			  size_t length)
    {
    assert(mem->allocated >= offset+length);
    
    while(length--)
	mem->buf[offset++]=n >> (length*8);
    }

void ops_memory_release(ops_memory_t *mem)
    {
    free(mem->buf);
    mem->buf=NULL;
    }

ops_writer_ret_t ops_writer_memory(const unsigned char *src,unsigned length,
				   ops_writer_flags_t flags,void *arg_)
    {
    ops_memory_t *mem=arg_;

    ops_memory_add(mem,src,length);
    return OPS_W_OK;
    }
