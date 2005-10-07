#include "armour.h"
#include "util.h"

#include <string.h>

typedef struct
    {
    ops_packet_reader_t *reader;
    void *reader_arg;
    enum
	{
	OUTSIDE_BLOCK=0,
	BASE64,
	AT_TRAILER_NAME,
	} state;
    ops_region_t *region;
    ops_parse_options_t *opt;
    ops_boolean_t seen_nl;
    } dearmour_arg_t;

// FIXME: move these to a common header
#define CB(t,pc)	do { (pc)->tag=(t); if(arg->opt->cb(pc,arg->opt->cb_arg) == OPS_RELEASE_MEMORY) ops_parser_content_free(pc); } while(0)
#define ERR(err)	do { content.content.error.error=err; content.tag=OPS_PARSER_ERROR; arg->opt->cb(&content,arg->opt->cb_arg); return OPS_R_EARLY_EOF; } while(0)

static int read_char(dearmour_arg_t *arg,ops_boolean_t skip)
    {
    unsigned char c[1];
    ops_packet_reader_t *reader;

    reader=arg->opt->reader;
    arg->opt->reader=arg->reader;
    arg->opt->reader_arg=arg->reader_arg;

    do
	{
	if(!ops_limited_read(c,1,arg->region,arg->opt))
	    return -1;
	}
    while(skip && c[0] == '\r');

    arg->opt->reader=reader;
    arg->opt->reader_arg=arg;

    arg->seen_nl=c[0] == '\n';

    return c[0];
    }    

static ops_reader_ret_t process_dash_escaped(dearmour_arg_t *arg)
    {
    ops_parser_content_t content;
    ops_signed_cleartext_body_t *body=&content.content.signed_cleartext_body;

    body->length=0;
    for( ; ; )
	{
	int c;
	unsigned count;

	ops_boolean_t t=arg->seen_nl;
	if((c=read_char(arg,ops_false)) < 0)
	    return OPS_R_EOF;
	if(t && c == '-')
	    {
	    if((c=read_char(arg,ops_false)) < 0)
		return OPS_R_EOF;
	    if(c != ' ')
		{
		/* then this had better be a trailer! */
		if(c != '-')
		    ERR("Bad dash-escaping");
		for(count=2 ; count < 5 ; ++count)
		    {
		    if((c=read_char(arg,ops_false)) < 0)
			return OPS_R_EOF;
		    if(c != '-')
			ERR("Bad dash-escaping (2)");
		    }
		arg->state=AT_TRAILER_NAME;
		break;
		}
	    /* otherwise we read the next character */
	    if((c=read_char(arg,ops_false)) < 0)
		return OPS_R_EOF;
	    }
	body->data[body->length++]=c;
	if(body->length == sizeof body->data)
	    {
	    CB(OPS_PTAG_CT_SIGNED_CLEARTEXT_BODY,&content);
	    body->length=0;
	    }
	}

    if(body->length)
	CB(OPS_PTAG_CT_SIGNED_CLEARTEXT_BODY,&content);

    return OPS_R_OK;
    }

// This reader is rather strange in that it can generate callbacks for
// content - this is because plaintext is not encapsulated in PGP packets...

static ops_reader_ret_t armoured_data_reader(unsigned char *dest,
					     unsigned *plength,
					     ops_reader_flags_t flags,
					     void *arg_)
    {
    dearmour_arg_t *arg=arg_;
    unsigned length=*plength;
    ops_parser_content_t content;

    while(length > 0)
	{
	unsigned count;
	unsigned n;
	char buf[1024];
	int c;

	switch(arg->state)
	    {
	case OUTSIDE_BLOCK:
	    while(!arg->seen_nl)
		if((c=read_char(arg,ops_true)) < 0)
		    return OPS_R_EOF;
		
	    /* Find and consume the 5 leading '-' */
	    for(count=0 ; count < 5 ; )
		{
		if((c=read_char(arg,ops_false)) < 0)
		    return OPS_R_EOF;
		if(c == '-')
		    ++count;
		else
		    count=0;
		}

	    /* Now find the block type */
	    for(n=0 ; n < sizeof buf-1 ; )
		{
		if((c=read_char(arg,ops_false)) < 0)
		    return OPS_R_EOF;
		if(c == '-')
		    goto got_minus;
		buf[n++]=c;
		}
	    /* then I guess this wasn't a proper header */
	    break;

	got_minus:
	    buf[n]='\0';

	    /* Consume trailing '-' */
	    for(count=1 ; count < 5 ; ++count)
		{
		if((c=read_char(arg,ops_false)) < 0)
		    return OPS_R_EOF;
		if(c != '-')
		    /* wasn't a header after all */
		    goto reloop;
		}

	    /* Consume final NL */
	    if((c=read_char(arg,ops_true)) < 0)
		return OPS_R_EOF;
	    if(c != '\n')
		/* wasn't a header line after all */
		break;

	    /* FIXME: parse headers */
	    for(count=1 ; count < 2 ; )
		{
		if((c=read_char(arg,ops_false)) < 0)
		    return OPS_R_EOF;
		if(c == '\n')
		    ++count;
		else
		    count=0;
		}

	    if(!strcmp(buf,"BEGIN PGP SIGNED MESSAGE"))
		{
		ops_reader_ret_t ret;
		CB(OPS_PTAG_CT_SIGNED_CLEARTEXT_HEADER,&content);
		ret=process_dash_escaped(arg);
		if(ret != OPS_R_OK)
		    return ret;
		}
	    else
		{
		content.content.armour_header.type=buf;
		CB(OPS_PTAG_CT_ARMOUR_HEADER,&content);
		arg->state=BASE64;
		}
	    break;

	case BASE64:
	    break;

	case AT_TRAILER_NAME:
	    for(n=0 ; n < sizeof buf-1 ; )
		{
		if((c=read_char(arg,ops_false)) < 0)
		    return OPS_R_EOF;
		if(c == '-')
		    goto got_minus2;
		buf[n++]=c;
		}
	    /* then I guess this wasn't a proper trailer */
	    ERR("Bad ASCII armour trailer");
	    break;

	got_minus2:
	    buf[n]='\0';

	    /* Consume trailing '-' */
	    for(count=1 ; count < 5 ; ++count)
		{
		if((c=read_char(arg,ops_false)) < 0)
		    return OPS_R_EOF;
		if(c != '-')
		    /* wasn't a trailer after all */
		    ERR("Bad ASCII armour trailer (2)");
		}

	    /* Consume final NL */
	    if((c=read_char(arg,ops_true)) < 0)
		return OPS_R_EOF;
	    if(c != '\n')
		/* wasn't a trailer line after all */
		ERR("Bad ASCII armour trailer (3)");

	    if(!strncmp(buf,"BEGIN ",6))
		{
		content.content.armour_header.type=buf;
		CB(OPS_PTAG_CT_ARMOUR_HEADER,&content);
		arg->state=BASE64;
		}
	    else
		{
		content.content.armour_trailer.type=buf;
		CB(OPS_PTAG_CT_ARMOUR_TRAILER,&content);
		arg->state=OUTSIDE_BLOCK;
		}
	    break;
	    }
    reloop:
	continue;
	}

    return OPS_R_OK;
    }

int ops_dearmour(ops_region_t *region,ops_parse_options_t *opt)
    {
    dearmour_arg_t arg;

    memset(&arg,'\0',sizeof arg);

    arg.reader_arg=opt->reader_arg;
    arg.reader=opt->reader;
    arg.region=region;
    arg.opt=opt;
    arg.seen_nl=ops_true;

    opt->reader=armoured_data_reader;
    opt->reader_arg=&arg;

    return ops_parse(opt);
    }
