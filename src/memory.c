/** \file
 */

#include <openpgpsdk/create.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct ops_memory
    {
    unsigned char *buf;
    size_t length;
    size_t allocated;
    };

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

/**
 * Unlike ops_memory_release(), this retains the allocated memory but
 * sets the length of stored data to zero.
 */
void ops_memory_clear(ops_memory_t *mem)
    { mem->length=0; }

void ops_memory_release(ops_memory_t *mem)
    {
    free(mem->buf);
    mem->buf=NULL;
    mem->length=0;
    }

static ops_boolean_t memory_writer(const unsigned char *src,unsigned length,
				      ops_error_t **errors,
				      ops_writer_info_t *winfo)
    {
    ops_memory_t *mem=ops_writer_get_arg(winfo);

    OPS_USED(errors);
    ops_memory_add(mem,src,length);
    return ops_true;
    }

/**
 * \ingroup Create
 *
 * Set a memory writer. Note that it is the caller's resposibility to
 * release mem.
 *
 * \param info The info structure
 * \param mem The memory structure */

void ops_writer_set_memory(ops_create_info_t *info,ops_memory_t *mem)
    {
    ops_writer_set(info,memory_writer,NULL,NULL,mem);
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

ops_memory_t *ops_memory_new()
    { return ops_mallocz(sizeof(ops_memory_t)); }

void ops_memory_free(ops_memory_t *mem)
    {
    ops_memory_release(mem);
    free(mem);
    }

size_t ops_memory_get_length(const ops_memory_t *mem)
    { return mem->length; }

void *ops_memory_get_data(ops_memory_t *mem)
    { return mem->buf; }
