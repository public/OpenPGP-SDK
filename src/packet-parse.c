#include "packet.h"
#include "packet-parse.h"
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>

#define CB(t,pc)	do { (pc)->tag=(t); cb(pc); } while(0)
#define C		content.content

/* Note that this makes the parser non-reentrant, in a limited way */
/* It is the caller's responsibility to avoid overflow in the buffer */
static void format_error(ops_parser_content *content,
			 const char * const fmt,...)
    {
    va_list va;
    static char buf[8192];

    va_start(va,fmt);
    vsprintf(buf,fmt,va);
    va_end(va);
    content->content.error.error=buf;
    }

static ops_packet_reader_ret read_scalar(unsigned *result,
					 ops_packet_reader *reader,
					 unsigned length)
    {
    unsigned t=0;
    ops_packet_reader_ret ret;

    while(length--)
	{
	unsigned char c[1];

	ret=reader(c,1);
	if(ret != OPS_PR_OK)
	    return ret;
	t=(t << 8)+c[0];
	}
    *result=t;
    return OPS_PR_OK;
    }

static int limited_read(unsigned char *dest,unsigned length,
			ops_parser_ptag *ptag,ops_packet_reader *reader,
			ops_packet_parse_callback *cb)
    {
    ops_parser_content content;

    if(ptag->length_read+length > ptag->length)
	{
	C.error.error="Not enough data left";
	CB(OPS_PARSER_ERROR,&content);
	return 0;
	}

    if(reader(dest,length) != OPS_PR_OK)
	{
	C.error.error="Read failed";
	CB(OPS_PARSER_ERROR,&content);
	return 0;
	}

    ptag->length_read+=length;

    return 1;
    }
    
static int limited_read_scalar(unsigned *dest,unsigned length,
			       ops_parser_ptag *ptag,ops_packet_reader *reader,
			       ops_packet_parse_callback *cb)
    {
    unsigned char c[4];
    unsigned t;
    int n;

    if(!limited_read(c,length,ptag,reader,cb))
	return 0;

    for(t=0,n=0 ; n < length ; ++n)
	t=(t << 8)+c[n];
    *dest=t;

    return 1;
    }

static int limited_read_time(time_t *dest,ops_parser_ptag *ptag,
			     ops_packet_reader *reader,
			     ops_packet_parse_callback *cb)
    {
    return limited_read_scalar((unsigned *)dest,4,ptag,reader,cb);
    }

static int limited_read_mpi(BIGNUM **pbn,ops_parser_ptag *ptag,
			    ops_packet_reader *reader,
			    ops_packet_parse_callback *cb)
    {
    unsigned length;
    unsigned nonzero;
    unsigned char buf[8192]; /* an MPI has a 2 byte length part.  Length
                                is given in bits, so the largest we should
                                ever need for the buffer is 8192 bytes. */
    ops_parser_content content;

    if(!limited_read_scalar(&length,2,ptag,reader,cb))
	return 0;

    nonzero=length&7; /* there should be this many zero bits in the MS byte */
    if(!nonzero)
	nonzero=8;
    length=(length+7)/8;

    assert(length <= 8192);
    if(!limited_read(buf,length,ptag,reader,cb))
	return 0;

    if((buf[0] >> nonzero) != 0 || !(buf[0]&(1 << (nonzero-1))))
	{
	C.error.error="MPI format error";
	CB(OPS_PARSER_ERROR,&content);
	return 0;
	}

    *pbn=BN_bin2bn(buf,length,NULL);
    return 1;
    }

static int parse_public_key(ops_parser_ptag *ptag,ops_packet_reader *reader,
			     ops_packet_parse_callback *cb)
    {
    ops_parser_content content;
    unsigned char c[1];

    if(!limited_read(c,1,ptag,reader,cb))
	return 0;
    C.public_key.version=c[0];
    /* XXX: Can this really be correct? What else is different with V2 keys? */
    if(C.public_key.version == 2)
	C.public_key.version=3;
    if(C.public_key.version != 3 && C.public_key.version != 4)
	{
	format_error(&content,"Bad public key version (0x%02x)",
		     C.public_key.version);
	CB(OPS_PARSER_ERROR,&content);
	return 0;
	}

    if(!limited_read_time(&C.public_key.creation_time,ptag,reader,cb))
	return 0;

    C.public_key.days_valid=0;
    if(C.public_key.version == 3
       && !limited_read_scalar(&C.public_key.days_valid,2,ptag,reader,
			       cb))
	return 0;

    if(!limited_read(c,1,ptag,reader,cb))
	return 0;
    C.public_key.algorithm=c[0];

    switch(C.public_key.algorithm)
	{
    case OPS_PKA_DSA:
	if(!limited_read_mpi(&C.public_key.key.dsa.p,ptag,reader,cb)
	   || !limited_read_mpi(&C.public_key.key.dsa.q,ptag,reader,cb)
	   || !limited_read_mpi(&C.public_key.key.dsa.g,ptag,reader,cb)
	   || !limited_read_mpi(&C.public_key.key.dsa.y,ptag,reader,cb))
	    return 0;
	break;
    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:
	if(!limited_read_mpi(&C.public_key.key.rsa.n,ptag,reader,cb)
	   || !limited_read_mpi(&C.public_key.key.rsa.e,ptag,reader,cb))
	    return 0;
	break;

    default: assert(0);
	}

    if(ptag->length_read != ptag->length)
	{
	format_error(&content,"Unconsumed data (%d)",
		     ptag->length-ptag->length_read);
	CB(OPS_PARSER_ERROR,&content);
	}

    CB(OPS_PTAG_CT_PUBLIC_KEY,&content);

    return 1;
    }

static int parse_user_id(ops_parser_ptag *ptag,ops_packet_reader *reader,
			 ops_packet_parse_callback *cb)
    {
    ops_parser_content content;

    assert(ptag->length);
    C.user_id.user_id=malloc(ptag->length);
    if(!limited_read(C.user_id.user_id,ptag->length,ptag,reader,cb))
	return 0;

    CB(OPS_PTAG_CT_USER_ID,&content);

    return 1;
    }

static int ops_parse_one_packet(ops_packet_reader *reader,
				ops_packet_parse_callback *cb)
    {
    char ptag[1];
    ops_packet_reader_ret ret;
    ops_parser_content content;
    int r;

    ret=reader(ptag,1);
    if(ret == OPS_PR_EOF)
	return 0;
    assert(ret == OPS_PR_OK);
    if(!(*ptag&OPS_PTAG_ALWAYS_SET))
	{
	C.error.error="Format error (ptag bit not set)";
	CB(OPS_PARSER_ERROR,&content);
	return 0;
	}
    C.ptag.new_format=!!(*ptag&OPS_PTAG_NEW_FORMAT);
    if(C.ptag.new_format)
	{
	C.ptag.content_tag=*ptag&OPS_PTAG_NF_CONTENT_TAG_MASK;
	C.ptag.length_type=0;
	}
    else
	{
	C.ptag.content_tag=(*ptag&OPS_PTAG_OF_CONTENT_TAG_MASK)
	    >> OPS_PTAG_OF_CONTENT_TAG_SHIFT;
	C.ptag.length_type=*ptag&0x03;
	switch(C.ptag.length_type)
	    {
	case OPS_PTAG_OF_LT_ONE_BYTE:
	    ret=read_scalar(&C.ptag.length,reader,1);
	    assert(ret == OPS_PR_OK);
	    break;

	case OPS_PTAG_OF_LT_TWO_BYTE:
	    ret=read_scalar(&C.ptag.length,reader,2);
	    assert(ret == OPS_PR_OK);
	    break;

	case OPS_PTAG_OF_LT_FOUR_BYTE:
	    ret=read_scalar(&C.ptag.length,reader,4);
	    assert(ret == OPS_PR_OK);
	    break;

	case OPS_PTAG_OF_LT_INDETERMINATE:
	    C.ptag.length=-1;
	    break;
	    }
	}

    C.ptag.length_read=0;
    CB(OPS_PARSER_PTAG,&content);

    switch(C.ptag.content_tag)
	{
    case OPS_PTAG_CT_PUBLIC_KEY:
	r=parse_public_key(&C.ptag,reader,cb);
	break;

    case OPS_PTAG_CT_USER_ID:
	r=parse_user_id(&C.ptag,reader,cb);
	break;

    default:
	format_error(&content,"Format error (unknown content tag %d)",
		     C.ptag.content_tag);
	CB(OPS_PARSER_ERROR,&content);
	r=0;
	}
    return r;
    }

void ops_parse_packet(ops_packet_reader *reader,ops_packet_parse_callback *cb)
    {
    while(ops_parse_one_packet(reader,cb))
	;
    }
