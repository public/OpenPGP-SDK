/** \file
 */

#include <openpgpsdk/create.h>
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

static ops_writer_ret_t memory_writer(const unsigned char *src,unsigned length,
				      ops_writer_flags_t flags,
				      ops_error_t **errors,
				      void *arg)
    {
    ops_memory_t *mem=arg;

    OPS_USED(flags);
    OPS_USED(errors);
    ops_memory_add(mem,src,length);
    return OPS_W_OK;
    }

/**
 * \ingroup Create
 *
 * Set a memory writer. Note that it is the caller's resposibility to
 * release mem.
 *
 * \param info The info structure
 * \param mem The memory structure
 */

void ops_create_info_set_writer_memory(ops_create_info_t *info,
				       ops_memory_t *mem)
    {
    ops_create_info_set_writer(info,memory_writer,NULL,mem);
    }

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
