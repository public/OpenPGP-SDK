/** \file
 */

#include "packet.h"
#include "util.h"
#include "build.h"
#include <stdlib.h>
#include <openssl/bn.h>
#include <assert.h>
#include <string.h>

// XXX: move this to memory.c?
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
