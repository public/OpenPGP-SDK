#include "armour.h"
#include "util.h"

#include <string.h>
#include <assert.h>

#define CRC24_INIT 0xb704ceL
#define CRC24_POLY 0x1864cfbL

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
    ops_boolean_t prev_nl;
    // base64 stuff
    unsigned buffered;
    unsigned char buffer[3];
    ops_boolean_t eof64;
    unsigned long checksum;
    unsigned long read_checksum;
    // unarmoured text blocks
    unsigned char unarmoured[8192];
    size_t num_unarmoured;
    // pushed back data (stored backwards)
    unsigned char *pushed_back;
    unsigned npushed_back;
    // armoured block headers
    ops_armoured_header_value_t **headers;
    unsigned nheaders;
    } dearmour_arg_t;

// FIXME: move these to a common header
#define CB(t,pc)	do { (pc)->tag=(t); if(arg->opt->cb(pc,arg->opt->cb_arg) == OPS_RELEASE_MEMORY) ops_parser_content_free(pc); } while(0)
#define ERR(err)	do { content.content.error.error=err; content.tag=OPS_PARSER_ERROR; arg->opt->cb(&content,arg->opt->cb_arg); return OPS_R_EARLY_EOF; } while(0)

static void push_back(dearmour_arg_t *arg,const unsigned char *buf,
		      unsigned length)
    {
    int n;

    assert(!arg->pushed_back);
    arg->pushed_back=malloc(length);
    for(n=0 ; n < length ; ++n)
	arg->pushed_back[n]=buf[length-n-1];
    arg->npushed_back=length;
    }
    
static int read_char(dearmour_arg_t *arg,ops_boolean_t skip)
    {
    unsigned char c[1];
    ops_packet_reader_t *reader;

    reader=arg->opt->reader;
    arg->opt->reader=arg->reader;
    arg->opt->reader_arg=arg->reader_arg;

    do
	{
	if(arg->npushed_back)
	    {
	    c[0]=arg->pushed_back[--arg->npushed_back];
	    if(!arg->npushed_back)
		{
		free(arg->pushed_back);
		arg->pushed_back=NULL;
		}
	    }
	else if(!ops_limited_read(c,1,arg->region,arg->opt))
	    return -1;
	}
    while(skip && c[0] == '\r');

    arg->opt->reader=reader;
    arg->opt->reader_arg=arg;

    arg->prev_nl=arg->seen_nl;
    arg->seen_nl=c[0] == '\n';

    return c[0];
    }

static void flush(dearmour_arg_t *arg)
    {
    ops_parser_content_t content;

    if(arg->num_unarmoured == 0)
	return;

    content.content.unarmoured_text.data=arg->unarmoured;
    content.content.unarmoured_text.length=arg->num_unarmoured;
    CB(OPS_PTAG_CT_UNARMOURED_TEXT,&content);
    arg->num_unarmoured=0;
    }

static int unarmoured_read_char(dearmour_arg_t *arg,ops_boolean_t skip)
    {
    int c;

    do
	{
	c=read_char(arg,ops_false);
	if(c < 0)
	    return c;
	arg->unarmoured[arg->num_unarmoured++]=c;
	if(arg->num_unarmoured == sizeof arg->unarmoured)
	    flush(arg);
	}
    while(skip && c == '\r');

    return c;
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

	if((c=read_char(arg,ops_false)) < 0)
	    return OPS_R_EARLY_EOF;
	if(arg->prev_nl && c == '-')
	    {
	    if((c=read_char(arg,ops_false)) < 0)
		return OPS_R_EARLY_EOF;
	    if(c != ' ')
		{
		/* then this had better be a trailer! */
		if(c != '-')
		    ERR("Bad dash-escaping");
		for(count=2 ; count < 5 ; ++count)
		    {
		    if((c=read_char(arg,ops_false)) < 0)
			return OPS_R_EARLY_EOF;
		    if(c != '-')
			ERR("Bad dash-escaping (2)");
		    }
		arg->state=AT_TRAILER_NAME;
		break;
		}
	    /* otherwise we read the next character */
	    if((c=read_char(arg,ops_false)) < 0)
		return OPS_R_EARLY_EOF;
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

static void add_header(dearmour_arg_t *arg,const char *key,const char
		       *value)
    {
    ops_armoured_header_value_t *header;

    header=malloc(sizeof *header);
    header->key=strdup(key);
    header->value=strdup(value);

    arg->headers=realloc(arg->headers,(arg->nheaders+1)*sizeof *arg->headers);
    arg->headers[arg->nheaders++]=header;
    }

static ops_reader_ret_t parse_headers(dearmour_arg_t *arg)
    {
    char *buf;
    unsigned nbuf;
    unsigned size;
    ops_boolean_t first=ops_true;
    ops_parser_content_t content;

    buf=NULL;
    nbuf=size=0;

    for( ;  ; )
	{
	int c;

	if((c=read_char(arg,ops_true)) < 0)
	    return OPS_R_EARLY_EOF;

	if(c == '\n')
	    {
	    char *s;

	    if(nbuf == 0)
		break;

	    assert(nbuf < size);
	    buf[nbuf]='\0';

	    s=strchr(buf,':');
	    if(!s)
		if(!first && !arg->opt->armour_allow_headers_without_gap)
		    // then we have seriously malformed armour
		    ERR("No colon in armour header");
		else
		    {
		    if(first &&
		       !(arg->opt->armour_allow_headers_without_gap
			 || arg->opt->armour_allow_no_gap))
			ERR("No colon in armour header (2)");
		    // then we have a nasty armoured block with no
		    // headers, not even a blank line.
		    buf[nbuf]='\n';
		    push_back(arg,buf,nbuf+1);
		    break;
		    }
	    else
		{
		*s='\0';
		if(s[1] != ' ')
		    ERR("No space in armour header");
		add_header(arg,buf,s+2);
		nbuf=0;
		}
	    first=ops_false;
	    }
	else
	    {
	    if(size <= nbuf+1)
		{
		size+=size+80;
		buf=realloc(buf,size);
		}
	    buf[nbuf++]=c;
	    }
	}

    free(buf);

    return OPS_R_OK;
    }

static ops_reader_ret_t read4(dearmour_arg_t *arg,int *pc,int *pn,
			      unsigned long *pl)
    {
    int n,c;
    unsigned long l=0;

    for(n=0 ; n < 4 ; ++n)
	{
	c=read_char(arg,ops_true);
	if(c < 0)
	    {
	    arg->eof64=ops_true;
	    return OPS_R_EARLY_EOF;
	    }
	if(c == '-')
	    break;
	if(c == '=')
	    break;
	l <<= 6;
	if(c >= 'A' && c <= 'Z')
	    l+=c-'A';
	else if(c >= 'a' && c <= 'z')
	    l+=c-'a'+26;
	else if(c >= '0' && c <= '9')
	    l+=c-'0'+52;
	else if(c == '+')
	    l+=62;
	else if(c == '/')
	    l+=63;
	else
	    {
	    --n;
	    l >>= 6;
	    }
	}

    *pc=c;
    *pn=n;
    *pl=l;

    return OPS_R_OK;
    }

static ops_reader_ret_t decode64(dearmour_arg_t *arg)
    {
    int n;
    unsigned long l;
    ops_parser_content_t content;
    int c;
    ops_reader_ret_t ret;

    assert(arg->buffered == 0);

    ret=read4(arg,&c,&n,&l);
    if(ret != OPS_R_OK)
	ERR("Badly formed base64");

    if(n == 3)
	{
	assert(c == '=');
	arg->buffered=2;
	arg->eof64=ops_true;
	l >>= 2;
	}
    else if(n == 2)
	{
	assert(c == '=');
	arg->buffered=1;
	arg->eof64=ops_true;
	l >>= 4;
	c=read_char(arg,ops_false);
	if(c != '=')
	    ERR("Badly terminated base64");
	}
    else if(n == 0)
	{
	assert(arg->prev_nl && c == '=');
	arg->buffered=0;
	}
    else
	{
	assert(n == 4);
	arg->buffered=3;
	assert(c != '-' && c != '=');
	}

    if(arg->buffered < 3 && arg->buffered > 0)
	{
	// then we saw padding
	assert(c == '=');
	c=read_char(arg,ops_true);
	if(c != '\n')
	    ERR("No newline at base64 end");
	c=read_char(arg,ops_false);
	if(c != '=')
	    ERR("No checksum at base64 end");
	}

    if(c == '=')
	{
	// now we are at the checksum
	ret=read4(arg,&c,&n,&arg->read_checksum);
	if(ret != OPS_R_OK || n != 4)
	    ERR("Error in checksum");
	c=read_char(arg,ops_true);
	if(c != '\n')
	    ERR("Badly terminated checksum");
	c=read_char(arg,ops_false);
	if(c != '-')
	    ERR("Bad base64 trailer (2)");
	}

    if(c == '-')
	{
	for(n=0 ; n < 4 ; ++n)
	    if(read_char(arg,ops_false) != '-')
		ERR("Bad base64 trailer");
	arg->eof64=ops_true;
	}
    else
	assert(arg->buffered);

    for(n=0 ; n < arg->buffered ; ++n)
	{
	arg->buffer[n]=l;
	l >>= 8;
	}

    for(n=arg->buffered-1 ; n >= 0 ; --n)
	{
	unsigned i;

	arg->checksum ^= arg->buffer[n] << 16;
	for(i=0 ; i < 8 ; i++)
	    {
	    arg->checksum <<= 1;
	    if(arg->checksum & 0x1000000)
		arg->checksum ^= CRC24_POLY;
	    }
	}
    arg->checksum &= 0xffffffL;

    if(arg->eof64 && arg->read_checksum != arg->checksum)
	ERR("Checksum mismatch");

    return OPS_R_OK;
    }

static void base64(dearmour_arg_t *arg)
    {
    arg->state=BASE64;
    arg->checksum=CRC24_INIT;
    arg->eof64=ops_false;
    arg->buffered=0;
    }

// This reader is rather strange in that it can generate callbacks for
// content - this is because plaintext is not encapsulated in PGP
// packets... it also calls back for the text between the blocks.

static ops_reader_ret_t armoured_data_reader(unsigned char *dest,
					     unsigned *plength,
					     ops_reader_flags_t flags,
					     void *arg_)
    {
    dearmour_arg_t *arg=arg_;
    unsigned length=*plength;
    ops_parser_content_t content;
    ops_reader_ret_t ret;
    ops_boolean_t first;

    if(arg->eof64 && !arg->buffered)
	assert(arg->state == OUTSIDE_BLOCK || arg->state == AT_TRAILER_NAME);

    while(length > 0)
	{
	unsigned count;
	unsigned n;
	char buf[1024];
	int c;

	switch(arg->state)
	    {
	case OUTSIDE_BLOCK:
	    /* This code returns EOF rather than EARLY_EOF because if
	       we don't see a header line at all, then it is just an
	       EOF (and not a BLOCK_END) */
	    while(!arg->seen_nl)
		if((c=unarmoured_read_char(arg,ops_true)) < 0)
		    return OPS_R_EOF;

	    /* flush at this point so we definitely have room for the
	       header, and so we can easily erase it from the buffer */
	    flush(arg);
	    /* Find and consume the 5 leading '-' */
	    for(count=0 ; count < 5 ; ++count)
		{
		if((c=unarmoured_read_char(arg,ops_false)) < 0)
		    return OPS_R_EOF;
		if(c != '-')
		    goto reloop;
		}

	    /* Now find the block type */
	    for(n=0 ; n < sizeof buf-1 ; )
		{
		if((c=unarmoured_read_char(arg,ops_false)) < 0)
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
		if((c=unarmoured_read_char(arg,ops_false)) < 0)
		    return OPS_R_EOF;
		if(c != '-')
		    /* wasn't a header after all */
		    goto reloop;
		}

	    /* Consume final NL */
	    if((c=unarmoured_read_char(arg,ops_true)) < 0)
		return OPS_R_EOF;
	    if(c != '\n')
		/* wasn't a header line after all */
		break;

	    /* Now we've seen the header, scrub it from the buffer */
	    arg->num_unarmoured=0;

	    /* But now we've seen a header line, then errors are
	       EARLY_EOF */
	    if((ret=parse_headers(arg)) != OPS_R_OK)
		return OPS_R_EARLY_EOF;

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
		base64(arg);
		}
	    break;

	case BASE64:
	    first=ops_true;
	    while(length > 0)
		{
		if(!arg->buffered)
		    {
		    if(!arg->eof64)
			{
			ret=decode64(arg);
			if(ret != OPS_R_OK)
			    return ret;
			}
		    if(!arg->buffered)
			{
			assert(arg->eof64);
			if(first)
			    {
			    arg->state=AT_TRAILER_NAME;
			    goto reloop;
			    }
			return OPS_R_EARLY_EOF;
			}
		    }
		
		assert(arg->buffered);
		*dest=arg->buffer[--arg->buffered];
		++dest;
		--length;
		first=ops_false;
		}
	    if(arg->eof64 && !arg->buffered)
		arg->state=AT_TRAILER_NAME;
	    break;

	case AT_TRAILER_NAME:
	    for(n=0 ; n < sizeof buf-1 ; )
		{
		if((c=read_char(arg,ops_false)) < 0)
		    return OPS_R_EARLY_EOF;
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
		    return OPS_R_EARLY_EOF;
		if(c != '-')
		    /* wasn't a trailer after all */
		    ERR("Bad ASCII armour trailer (2)");
		}

	    /* Consume final NL */
	    if((c=read_char(arg,ops_true)) < 0)
		return OPS_R_EARLY_EOF;
	    if(c != '\n')
		/* wasn't a trailer line after all */
		ERR("Bad ASCII armour trailer (3)");

	    if(!strncmp(buf,"BEGIN ",6))
		{
		if((ret=parse_headers(arg)) != OPS_R_OK)
		    return ret;
		content.content.armour_header.type=buf;
		CB(OPS_PTAG_CT_ARMOUR_HEADER,&content);
		base64(arg);
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
