/** \file
 */
  
#include <openpgpsdk/compress.h>
#include <zlib.h>
#include <assert.h>
#include <string.h>

#define DECOMPRESS_BUFFER	1024

typedef struct
    {
    ops_packet_reader_t *reader;
    void *reader_arg;
    ops_parse_options_t *opt;
    ops_region_t *region;
    unsigned char in[DECOMPRESS_BUFFER];
    unsigned char out[DECOMPRESS_BUFFER];
    z_stream stream;
    size_t offset;
    int inflate_ret;
    } decompress_arg_t;

#define ERR(err)	do { content.content.error.error=err; content.tag=OPS_PARSER_ERROR; arg->opt->cb(&content,arg->opt->cb_arg); return OPS_R_EARLY_EOF; } while(0)

static ops_reader_ret_t compressed_data_reader(unsigned char *dest,
					       unsigned *plength,
					       ops_reader_flags_t flags,
					       void *arg_)
    {
    decompress_arg_t *arg=arg_;
    ops_parser_content_t content;
    unsigned length=*plength;

    OPS_USED(flags);

    if(arg->region->indeterminate && arg->inflate_ret == Z_STREAM_END
       && arg->stream.next_out == &arg->out[arg->offset])
	return OPS_R_EOF;

    if(arg->region->length_read == arg->region->length)
	{
	if(arg->inflate_ret != Z_STREAM_END)
	    ERR("Compressed data didn't end when region ended.");
	else
	    return OPS_R_EOF;
	}

    while(length > 0)
	{
	unsigned len;

	if(&arg->out[arg->offset] == arg->stream.next_out)
	    {
	    int ret;

	    arg->stream.next_out=arg->out;
	    arg->stream.avail_out=sizeof arg->out;
	    arg->offset=0;
	    if(arg->stream.avail_in == 0)
		{
		unsigned n=arg->region->length;

		if(!arg->region->indeterminate)
		    {
		    n-=arg->region->length_read;
		    if(n > sizeof arg->in)
			n=sizeof arg->in;
		    }
		else
		    n=sizeof arg->in;

		arg->opt->reader=arg->reader;
		arg->opt->reader_arg=arg->reader_arg;

		if(!ops_limited_read(arg->in,n,arg->region,arg->opt))
		    return OPS_R_EARLY_EOF;

		arg->opt->reader=compressed_data_reader;
		arg->opt->reader_arg=arg;

		arg->stream.next_in=arg->in;
		arg->stream.avail_in=arg->region->indeterminate
		    ? arg->region->last_read : n;
		}

	    ret=inflate(&arg->stream,Z_SYNC_FLUSH);
	    if(ret == Z_STREAM_END)
		{
		if(!arg->region->indeterminate
		   && arg->region->length_read != arg->region->length)
		    ERR("Compressed stream ended before packet end.");
		}
	    else if(ret != Z_OK)
		{
		fprintf(stderr,"ret=%d\n",ret);
		ERR("Decompression error.");
		}
	    arg->inflate_ret=ret;
	    }
	assert(arg->stream.next_out > &arg->out[arg->offset]);
	len=arg->stream.next_out-&arg->out[arg->offset];
	if(len > length)
	    len=length;
	memcpy(dest,&arg->out[arg->offset],len);
	arg->offset+=len;
	length-=len;
	}

    return OPS_R_OK;
    }

/**
 * \ingroup Utils
 * 
 * \param *region 	Pointer to a region
 * \param *opt 		Options to use 
*/

int ops_decompress(ops_region_t *region,ops_parse_options_t *opt)
    {
    decompress_arg_t arg;
    int ret;

    memset(&arg,'\0',sizeof arg);

    arg.reader_arg=opt->reader_arg;
    arg.reader=opt->reader;
    arg.region=region;
    arg.opt=opt;

    arg.stream.next_in=Z_NULL;
    arg.stream.avail_in=0;
    arg.stream.next_out=arg.out;
    arg.offset=0;
    arg.stream.zalloc=Z_NULL;
    arg.stream.zfree=Z_NULL;

    ret=inflateInit2(&arg.stream,-15);
    if(ret != Z_OK)
	{
	fprintf(stderr,"ret=%d\n",ret);
	return 0;
	}

    opt->reader=compressed_data_reader;
    opt->reader_arg=&arg;

    return ops_parse(opt);
    }
