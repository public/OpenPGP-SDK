#include "packet.h"
#include "util.h"
#include "packet-parse.h"
#include <stdlib.h>
#include <assert.h>
#include <openssl/md5.h>

#ifdef DMALLOC
# include <dmalloc.h>
#endif

typedef struct
    {
    ops_packet_parse_callback_t *cb;
    void *cb_arg;
    ops_packet_reader_t *reader;
    unsigned char *packet;
    unsigned length;
    unsigned size;
    unsigned char *pkey_packet;
    unsigned pkey_length;
    unsigned char *uid_packet;
    unsigned uid_length;
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

static void verify(const ops_signature_t *sig,validate_arg_t *arg)
    {
    hash_t *hash=&md5;
    unsigned char hashout[MAX_HASH];
    unsigned n;

    assert(sig->version == OPS_SIG_V3);
    assert(sig->hash_algorithm == OPS_HASH_MD5);

    hash->init(hash);
    switch(sig->type)
	{
    case OPS_CERT_POSITIVE:
	hash_add_int(hash,0x99,1);
	hash_add_int(hash,arg->pkey_length,2);
	hash->add(hash,arg->pkey_packet,arg->pkey_length);
	hash->add(hash,arg->uid_packet,arg->uid_length);
	hash_add_int(hash,sig->type,1);
	hash_add_int(hash,sig->creation_time,4);
	break;

    default:
	assert(0);
	}

    n=hash->finish(hash,hashout);
    printf("hash=");
    hexdump(hashout,n);
    printf("\n");
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
	arg->pkey_length=arg->length;
	arg->packet=NULL;
	break;

    case OPS_PTAG_CT_USER_ID:
	/* Packet has ended */
	arg->uid_packet=arg->packet;
	arg->uid_length=arg->length;
	arg->packet=NULL;
	break;

    case OPS_PTAG_CT_SIGNATURE:
	verify(&content->signature,arg);
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
