#include "packet.h"
#include "packet-parse.h"
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>

#define CB(t,pc)	do { (pc)->tag=(t); cb(pc); } while(0)
#define C		content.content

#define E		CB(OPS_PARSER_ERROR,&content); return 0
#define ERR(err)	do { C.error.error=err; E; } while(0)
#define ERR1(fmt,x)	do { format_error(&content,(fmt),(x)); E; } while(0)

/* XXX: replace ops_ptag_t with something more appropriate for limiting
   reads */

/* Note that this makes the parser non-reentrant, in a limited way */
/* It is the caller's responsibility to avoid overflow in the buffer */
static void format_error(ops_parser_content_t *content,
			 const char * const fmt,...)
    {
    va_list va;
    static char buf[8192];

    va_start(va,fmt);
    vsprintf(buf,fmt,va);
    va_end(va);
    content->content.error.error=buf;
    }

static ops_packet_reader_ret_t read_scalar(unsigned *result,
					   ops_packet_reader_t *reader,
					   unsigned length)
    {
    unsigned t=0;
    ops_packet_reader_ret_t ret;

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
			ops_ptag_t *ptag,ops_packet_reader_t *reader,
			ops_packet_parse_callback_t *cb)
    {
    ops_parser_content_t content;

    if(ptag->length_read+length > ptag->length)
	ERR("Not enough data left");

    if(reader(dest,length) != OPS_PR_OK)
	ERR("Read failed");

    ptag->length_read+=length;

    return 1;
    }

static int limited_skip(unsigned length,ops_ptag_t *ptag,
			ops_packet_reader_t *reader,
			ops_packet_parse_callback_t *cb)
    {
    unsigned char buf[8192];

    while(length)
	{
	int n=length%8192;
	if(!limited_read(buf,n,ptag,reader,cb))
	    return 0;
	length-=n;
	}
    return 1;
    }
    
static int limited_read_scalar(unsigned *dest,unsigned length,
			       ops_ptag_t *ptag,ops_packet_reader_t *reader,
			       ops_packet_parse_callback_t *cb)
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

static int limited_read_time(time_t *dest,ops_ptag_t *ptag,
			     ops_packet_reader_t *reader,
			     ops_packet_parse_callback_t *cb)
    {
    return limited_read_scalar((unsigned *)dest,4,ptag,reader,cb);
    }

static int limited_read_mpi(BIGNUM **pbn,ops_ptag_t *ptag,
			    ops_packet_reader_t *reader,
			    ops_packet_parse_callback_t *cb)
    {
    unsigned length;
    unsigned nonzero;
    unsigned char buf[8192]; /* an MPI has a 2 byte length part.  Length
                                is given in bits, so the largest we should
                                ever need for the buffer is 8192 bytes. */
    ops_parser_content_t content;

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
	ERR("MPI format error");

    *pbn=BN_bin2bn(buf,length,NULL);
    return 1;
    }

static int limited_read_new_length(unsigned *length,ops_ptag_t *ptag,
				   ops_packet_reader_t *reader,
				   ops_packet_parse_callback_t *cb)
    {
    unsigned char c[1];

    if(!limited_read(c,1,ptag,reader,cb))
	return 0;
    if(c[0] < 192)
	{
	*length=c[0];
	return 1;
	}
    if(c[0] < 255)
	{
	unsigned t=(c[0]-192) << 8;

	if(!limited_read(c,1,ptag,reader,cb))
	    return 0;
	*length=t+c[1]+192;
	return 1;
	}
    return limited_read_scalar(length,4,ptag,reader,cb);
    }

static int parse_public_key(ops_ptag_t *ptag,ops_packet_reader_t *reader,
			     ops_packet_parse_callback_t *cb)
    {
    ops_parser_content_t content;
    unsigned char c[1];

    if(!limited_read(c,1,ptag,reader,cb))
	return 0;
    C.public_key.version=c[0];
    /* XXX: Can this really be correct? What else is different with V2 keys? */
    if(C.public_key.version == 2)
	C.public_key.version=3;
    if(C.public_key.version != 3 && C.public_key.version != 4)
	ERR1("Bad public key version (0x%02x)",C.public_key.version);

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
	ERR1("Unconsumed data (%d)", ptag->length-ptag->length_read);

    CB(OPS_PTAG_CT_PUBLIC_KEY,&content);

    return 1;
    }

static int parse_user_id(ops_ptag_t *ptag,ops_packet_reader_t *reader,
			 ops_packet_parse_callback_t *cb)
    {
    ops_parser_content_t content;

    assert(ptag->length);
    C.user_id.user_id=malloc(ptag->length);
    if(!limited_read(C.user_id.user_id,ptag->length,ptag,reader,cb))
	return 0;

    CB(OPS_PTAG_CT_USER_ID,&content);

    return 1;
    }

static int parse_v3_signature(ops_ptag_t *ptag,ops_packet_reader_t *reader,
			      ops_packet_parse_callback_t *cb)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    C.signature.version=OPS_SIG_V3;

    /* hash info length */
    if(!limited_read(c,1,ptag,reader,cb))
	return 0;
    if(c[0] != 5)
	ERR("bad hash info length");

    if(!limited_read(c,1,ptag,reader,cb))
	return 0;
    C.signature.type=c[0];
    /* XXX: check signature type */

    if(!limited_read_time(&C.signature.creation_time,ptag,reader,cb))
	return 0;

    if(!limited_read(C.signature.signer_id,8,ptag,reader,cb))
	return 0;

    if(!limited_read(c,1,ptag,reader,cb))
	return 0;
    C.signature.key_algorithm=c[0];
    /* XXX: check algorithm */

    if(!limited_read(c,1,ptag,reader,cb))
	return 0;
    C.signature.hash_algorithm=c[0];
    /* XXX: check algorithm */
    
    if(!limited_read(C.signature.hash2,2,ptag,reader,cb))
	return 0;

    switch(C.signature.key_algorithm)
	{
    case OPS_PKA_RSA:
	if(!limited_read_mpi(&C.signature.signature.rsa.sig,ptag,reader,cb))
	    return 0;
	break;

    case OPS_PKA_DSA:
	if(!limited_read_mpi(&C.signature.signature.dsa.r,ptag,reader,cb)
	   || !limited_read_mpi(&C.signature.signature.dsa.s,ptag,reader,cb))
	    return 0;
	break;

    default:
	ERR1("Bad signature key algorithm (%d)",C.signature.key_algorithm);
	}

    if(ptag->length_read != ptag->length)
	ERR1("Unconsumed data (%d)", ptag->length-ptag->length_read);

    CB(OPS_PTAG_CT_SIGNATURE,&content);

    return 1;
    }

static int parse_one_signature_subpacket(ops_ptag_t *ptag,
					 ops_packet_reader_t *reader,
					 ops_packet_parse_callback_t *cb,
					 ops_parse_packet_options_t *opt)
    {
    ops_ptag_t subptag;
    char c[1];
    ops_parser_content_t content;
    unsigned t8,t7;

    memset(&subptag,'\0',sizeof subptag);
    if(!limited_read_new_length(&subptag.length,ptag,reader,cb))
	return 0;

    if(!limited_read(c,1,&subptag,reader,cb))
	return 0;

    t8=(c[0]&0x7f)/8;
    t7=1 << (c[0]&7);

    content.critical=c[0] >> 7;
    content.tag=OPS_PTAG_SIGNATURE_SUBPACKET_BASE+(c[0]&0x7f);
    if(opt->ss_raw[t8]&t7)
	{
	C.ss_raw.tag=content.tag;
	C.ss_raw.raw=malloc(subptag.length-1);
	if(!limited_read(C.ss_raw.raw,subptag.length-1,ptag,reader,cb))
	    return 0;
	ptag->length_read+=subptag.length;
	CB(OPS_PTAG_RAW_SS,&content);
	return 1;
	}
    if(!(opt->ss_parsed[t8]&t7))
	{
	if(content.critical)
	    ERR1("Critical signature subpacket ignored (%d)",c[0]&0x7f);
	if(!limited_skip(subptag.length-1,&subptag,reader,cb))
	    return 0;
	printf("skipped %d length %d\n",c[0]&0x7f,subptag.length);
	ptag->length_read+=subptag.length;
	return 1;
	}

    switch(content.tag)
	{
    case OPS_PTAG_SS_TRUST:
	if(!limited_read(&C.ss_trust.level,1,&subptag,reader,cb)
	   || !limited_read(&C.ss_trust.level,1,&subptag,reader,cb))
	    return 0;
	break;

    default:
	ERR1("Unknown signature subpacket type (%d)",c[0]&0x7f);
	}
 
    ptag->length_read+=subptag.length;
    cb(&content);

    return 1;
    }

static int parse_signature_subpackets(ops_ptag_t *ptag,
				      ops_packet_reader_t *reader,
				      ops_packet_parse_callback_t *cb,
				      ops_parse_packet_options_t *opt)
    {
    ops_ptag_t subptag;

    memset(&subptag,'\0',sizeof subptag);
    if(!limited_read_scalar(&subptag.length,2,ptag,reader,cb))
	return 0;

    while(subptag.length_read < subptag.length)
	if(!parse_one_signature_subpacket(&subptag,reader,cb,opt))
	    {
	    ptag->length_read+=subptag.length_read;
	    return 0;
	    }

    assert(subptag.length_read == subptag.length);
    ptag->length_read+=subptag.length_read;

    return 1;
    }

static int parse_v4_signature(ops_ptag_t *ptag,ops_packet_reader_t *reader,
			      ops_packet_parse_callback_t *cb,
			      ops_parse_packet_options_t *opt)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    C.signature.version=OPS_SIG_V4;

    if(!limited_read(c,1,ptag,reader,cb))
	return 0;
    C.signature.type=c[0];
    /* XXX: check signature type */

    if(!limited_read(c,1,ptag,reader,cb))
	return 0;
    C.signature.key_algorithm=c[0];
    /* XXX: check algorithm */

    if(!limited_read(c,1,ptag,reader,cb))
	return 0;
    C.signature.hash_algorithm=c[0];
    /* XXX: check algorithm */
    
    if(!parse_signature_subpackets(ptag,reader,cb,opt))
	return 0;

    if(!parse_signature_subpackets(ptag,reader,cb,opt))
	return 0;

    

    if(!limited_read(C.signature.hash2,2,ptag,reader,cb))
	return 0;

    switch(C.signature.key_algorithm)
	{
    case OPS_PKA_RSA:
	if(!limited_read_mpi(&C.signature.signature.rsa.sig,ptag,reader,cb))
	    return 0;
	break;

    case OPS_PKA_DSA:
	if(!limited_read_mpi(&C.signature.signature.dsa.r,ptag,reader,cb)
	   || !limited_read_mpi(&C.signature.signature.dsa.s,ptag,reader,cb))
	    return 0;
	break;

    default:
	ERR1("Bad signature key algorithm (%d)",C.signature.key_algorithm);
	}

    if(ptag->length_read != ptag->length)
	ERR1("Unconsumed data (%d)", ptag->length-ptag->length_read);

    CB(OPS_PTAG_CT_SIGNATURE,&content);

    return 1;
    }

static int parse_signature(ops_ptag_t *ptag,ops_packet_reader_t *reader,
			   ops_packet_parse_callback_t *cb,
			   ops_parse_packet_options_t *opt)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    if(!limited_read(c,1,ptag,reader,cb))
	return 0;

    /* XXX: More V2 issues! */
    if(c[0] == 2 || c[0] == 3)
	return parse_v3_signature(ptag,reader,cb);
    else if(c[0] == 4)
	return parse_v4_signature(ptag,reader,cb,opt);
    ERR1("Bad signature version (%d)",c[0]);
    }

static int ops_parse_one_packet(ops_packet_reader_t *reader,
				ops_packet_parse_callback_t *cb,
				ops_parse_packet_options_t *opt)
    {
    char ptag[1];
    ops_packet_reader_ret_t ret;
    ops_parser_content_t content;
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
    case OPS_PTAG_CT_SIGNATURE:
	r=parse_signature(&C.ptag,reader,cb,opt);
	break;

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

void ops_parse_packet(ops_packet_reader_t *reader,
		      ops_packet_parse_callback_t *cb,
		      ops_parse_packet_options_t *opt)
    {
    while(ops_parse_one_packet(reader,cb,opt))
	;
    }

void ops_parse_packet_options(ops_parse_packet_options_t *opt,
			      ops_content_tag_t tag,
			      ops_parse_type_t type)
    {
    int t8,t7;

    assert(tag >= OPS_PTAG_SIGNATURE_SUBPACKET_BASE
	   && tag <= OPS_PTAG_SIGNATURE_SUBPACKET_BASE+255);
    t8=(tag-OPS_PTAG_SIGNATURE_SUBPACKET_BASE)/8;
    t7=1 << ((tag-OPS_PTAG_SIGNATURE_SUBPACKET_BASE)&7);
    switch(type)
	{
    case OPS_PARSE_RAW:
	opt->ss_raw[t8] |= t7;
	opt->ss_parsed[t8] &= ~t7;
	break;

    case OPS_PARSE_PARSED:
	opt->ss_raw[t8] &= ~t7;
	opt->ss_parsed[t8] |= t7;
	break;

    case OPS_PARSE_IGNORE:
	opt->ss_raw[t8] &= ~t7;
	opt->ss_parsed[t8] &= ~t7;
	break;
	}
    }

	
