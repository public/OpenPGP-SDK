#include "packet.h"
#include "packet-parse.h"
#include <stdlib.h>
#include <assert.h>

typedef struct
    {
    ops_packet_parse_callback_t *cb;
    void *cb_arg;
    ops_packet_reader_t *reader;
    unsigned char *packet;
    unsigned length;
    unsigned size;
    unsigned char *pkey_packet;
    unsigned char *uid_packet;
    } validate_arg_t;

static ops_packet_reader_ret_t val_reader(unsigned char *dest,unsigned length,
					  void *arg_)
    {
    validate_arg_t *arg=arg_;
    ops_packet_reader_ret_t ret=arg->reader(dest,length,arg->cb_arg);

    if(ret != OPS_PR_OK || !arg->packet)
	return ret;

    if(arg->length+length > arg->size)
	{
	unsigned ns=arg->size*2 > arg->length+length ? arg->size*2
	    : arg->size+length;
	arg->packet=realloc(arg->packet,ns);
	arg->size=ns;
	}
    assert(arg->length+length <= arg->size);
    memcpy(arg->packet+arg->length,dest,length);
    arg->length+=length;

    return ret;
    }

static void validate_cb(const ops_parser_content_t *content_,void *arg_)
    {
    validate_arg_t *arg=arg_;
    const ops_parser_content_union_t *content=&content_->content;

    // XXX: clean up saved pkay and uid...
    switch(content_->tag)
	{
    case OPS_PARSER_PTAG:
	/* Packet has just started */
	switch(content->ptag.content_tag)
	    {
	case OPS_PTAG_CT_PUBLIC_KEY:
	case OPS_PTAG_CT_USER_ID:
	    arg->packet=malloc(128);
	    arg->size=128;
	    arg->length=1;
	    arg->packet[0]=content->ptag.content_tag;
	    break;
	    }
	break;

    case OPS_PTAG_CT_PUBLIC_KEY:
	/* Packet has ended */
	arg->pkey_packet=arg->packet;
	arg->packet=NULL;
	break;

    case OPS_PTAG_CT_USER_ID:
	/* Packet has ended */
	arg->uid_packet=arg->packet;
	arg->packet=NULL;
	break;

    default:
	break;
	}

    arg->cb(content_,arg->cb_arg);
    }

void ops_parse_and_validate(ops_parse_options_t *opt)
    {
    validate_arg_t arg;

    arg.cb=opt->cb;
    arg.cb_arg=opt->cb_arg;
    arg.reader=opt->reader;
    arg.packet=NULL;
    arg.length=0;
    arg.size=0;
    opt->cb=validate_cb;
    opt->cb_arg=&arg;
    opt->reader=val_reader;
    ops_parse(opt);
    }
