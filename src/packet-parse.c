/** \file packet-parse.c
 * Parser for OpenPGP packets.
 *
 * $Id$
 */

#include "packet.h"
#include "packet-parse.h"
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

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

/** Read a scalar value of selected length from reader.
 *
 * Read an unsigned scalar value from reader in Big Endian representation.
 *
 * This function does not know or care about packet boundaries.
 *
 * \param *result	The scalar value is stored here
 * \param *reader	Our reader
 * \param length	How many bytes to read
 * \return		#OPS_PR_OK on success, reader's return value otherwise
 *
 */
static ops_packet_reader_ret_t read_scalar(unsigned *result,
					   ops_packet_reader_t *reader,
					   unsigned length)
    {
    unsigned t=0;
    ops_packet_reader_ret_t ret;

    assert (length <= sizeof(*result));

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

/** Read bytes from reader.
 *
 * Read length bytes into the buffer pointed to by *dest.  Make sure we do not read over the packet boundary.  Updates
 * the Packet Tag's ops_ptag_t::length_read.
 *
 * If length would make us read over the packet boundary, or if reading fails, we call the callback with an
 * #OPS_PARSER_ERROR.
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param *dest		The destination buffer
 * \param length	How many bytes to read
 * \param *ptag		Pointer to current packet's Packet Tag
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		1 on success, 0 on error
 */
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

/** Skip over length bytes of this packet.
 *
 * Calls #limited_read to skip over some data.
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param length	How many bytes to skip
 * \param *ptag		Pointer to current packet's Packet Tag.
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		1 on success, 0 on error (calls the cb with #OPS_PARSER_ERROR in #limited_read).
 */
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

/** Read a scalar.
 *
 * Read a Big Endian scalar of length bytes, respecing packet boundaries (by calling #limited_read to read the raw
 * data).
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param *dest		The scalar value is stored here
 * \param length	How many bytes make up this scalar
 * \param *ptag		Pointer to current packet's Packet Tag.
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		1 on success, 0 on error (calls the cb with #OPS_PARSER_ERROR in #limited_read).
 *
 * \see RFC2440bis-12 3.1
 */
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

/** Read a timestamp.
 *
 * Timestamps in OpenPGP are unix time, i.e. seconds since The Epoch (1.1.1970).  They are stored in an unsigned scalar
 * of 4 bytes.
 *
 * This function reads the timestamp using #limited_read_scalar.
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param *dest		The timestamp is stored here
 * \param *ptag		Pointer to current packet's Packet Tag.
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		see #limited_read_scalar
 *
 * \see RFC2440bis-12 3.5
 */
static int limited_read_time(time_t *dest,ops_ptag_t *ptag,
			     ops_packet_reader_t *reader,
			     ops_packet_parse_callback_t *cb)
    {
    return limited_read_scalar((unsigned *)dest,4,ptag,reader,cb);
    }

/** Read a multiprecision integer.
 *
 * Large numbers (multiprecision integers, MPI) are stored in OpenPGP in two parts.  First there is a 2 byte scalar
 * indicating the length of the following MPI in Bits.  Then follow the bits that make up the actual number, most
 * significant bits first (Big Endian).  The most significant bit in the MPI is supposed to be 1 (unless the MPI is
 * encrypted - then it may be different as the bit count refers to the plain text but the bits are encrypted).
 *
 * Unused bits (i.e. those filling up the most significant byte from the left to the first bits that counts) are
 * supposed to be cleared - I guess. XXX - does anything actually say so?
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param **pgn		return the integer there - the BIGNUM is created by BN_bin2bn() and probably needs to be freed
 * 				by the caller XXX right ben?
 * \param *ptag		Pointer to current packet's Packet Tag.
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		1 on success, 0 on error (by #limited_read_scalar or #limited_read or if the MPI is not properly formed (XXX
 * 				 see comment below - the callback is called with a #OPS_PARSER_ERROR in case of an error)
 *
 * \see RFC2440bis-12 3.2
 */
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
	ERR("MPI format error");  /* XXX: Ben, one part of this constaint does not apply to encrypted MPIs the draft says. -- peter */

    *pbn=BN_bin2bn(buf,length,NULL);
    return 1;
    }

/** Read the length information for a new format Packet Tag.
 *
 * New style Packet Tags encode the length in one to five octets.  This function reads the right amount of bytes and
 * decodes it to the proper length information.
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param *length	return the length here
 * \param *ptag		Pointer to current packet's Packet Tag.
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		1 on success, 0 on error (by #limited_read_scalar or #limited_read or if the MPI is not properly formed (XXX
 * 				 see comment below)
 *
 * \see RFC2440bis-12 4.2.2
 * \see ops_ptag_t
 */
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

/** Parse a public key packet.
 *
 * This function parses an entire v3 (== v2) or v4 public key packet for RSA, ElGamal, and DSA keys.
 *
 * Once the key has been parsed successfully, it is passed to the callback.
 *
 * \param *ptag		Pointer to the current Packet Tag.  This function should consume the entire packet.
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		1 on success, 0 on error
 *
 * \see RFC2440bis-12 5.5.2
 */
static int parse_public_key(ops_ptag_t *ptag,ops_packet_reader_t *reader,
			     ops_packet_parse_callback_t *cb)
    {
    ops_parser_content_t content;
    unsigned char c[1];

    assert (ptag->length_read == 0);  /* We should not have read anything so far */

    if(!limited_read(c,1,ptag,reader,cb))
	return 0;
    C.public_key.version=c[0];
    /* XXX:- Can this really be correct? What else is different with V2 keys? -- Ben
     *     - David Shaw says the only difference is the version number, IIRC - I don't have email here - Peter */
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

    case OPS_PKA_ELGAMAL:
	if(!limited_read_mpi(&C.public_key.key.elgamel.p,ptag,reader,cb)
	   || !limited_read_mpi(&C.public_key.key.elgamel.g,ptag,reader,cb)
	   || !limited_read_mpi(&C.public_key.key.elgamel.y,ptag,reader,cb))
	    return 0;
	break;

    default:
	ERR1("Unknown public key algorithm (%d)",C.public_key.algorithm);
	}

    if(ptag->length_read != ptag->length)
	ERR1("Unconsumed data (%d)", ptag->length-ptag->length_read);

    CB(ptag->content_tag,&content);

    return 1;
    }

/** Parse a user id.
 *
 * This function parses an user id packet, which is basically just a char array the size of the packet.
 *
 * The char array is to be treated as an UTF-8 string.
 *
 * The userid gets null terminated by this function.  Freeing it is the responsibility of the caller.
 *
 * Once the userid has been parsed successfully, it is passed to the callback.
 *
 * \param *ptag		Pointer to the Packet Tag.  This function should consume the entire packet.
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		1 on success, 0 on error
 *
 * \see RFC2440bis-12 5.11
 */
static int parse_user_id(ops_ptag_t *ptag,ops_packet_reader_t *reader,
			 ops_packet_parse_callback_t *cb)
    {
    ops_parser_content_t content;

    assert (ptag->length_read == 0);  /* We should not have read anything so far */

    assert(ptag->length);
    C.user_id.user_id=malloc(ptag->length+1);  /* XXX should we not like check malloc's return value? */
    if(!limited_read(C.user_id.user_id,ptag->length,ptag,reader,cb))
	return 0;
    C.user_id.user_id[ptag->length] = 0; /* terminate the string */

    CB(OPS_PTAG_CT_USER_ID,&content);

    return 1;
    }

/** Parse a version 3 signature.
 *
 * This function parses an version 3 signature packet, handling RSA and DSA signatures.
 *
 * Once the signature has been parsed successfully, it is passed to the callback.
 *
 * \param *ptag		Pointer to the Packet Tag.  This function should consume the entire packet.
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		1 on success, 0 on error
 *
 * \see RFC2440bis-12 5.2.2
 */
static int parse_v3_signature(ops_ptag_t *ptag,ops_packet_reader_t *reader,
			      ops_packet_parse_callback_t *cb)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    assert (ptag->length_read == 0);  /* We should not have read anything so far */

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

/** Parse one signature sub-packet.
 *
 * Version 4 signatures can have an arbitrary amount of (hashed and unhashed) subpackets.  Subpackets are used to hold
 * optional attributes of subpackets.
 *
 * This function parses one such signature subpacket.
 *
 * Once the subpacket has been parsed successfully, it is passed to the callback.
 *
 * \param *ptag		Pointer to the Packet Tag.  This function should consume the entire subpacket.
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		1 on success, 0 on error
 *
 * \see RFC2440bis-12 5.2.3
 */
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
	C.ss_raw.length=subptag.length-1;
	C.ss_raw.raw=malloc(C.ss_raw.length);
	if(!limited_read(C.ss_raw.raw,C.ss_raw.length,&subptag,reader,cb))
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

    if(subptag.length_read != subptag.length)
	ERR1("Unconsumed data (%d)", subptag.length-subptag.length_read);
 
    ptag->length_read+=subptag.length;
    cb(&content);

    return 1;
    }

/** Parse several signature subpackets.
 *
 * Hashed and unhashed subpacket sets are preceded by an octet count that specifies the length of the complete set.
 * This function parses this length and then calls #parse_one_signature_subpacket for each subpacket until the
 * entire set is consumed.
 *
 * This function does not call the callback directly, #parse_one_signature_subpacket does for each subpacket.
 *
 * \param *ptag		Pointer to the Packet Tag.
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		1 on success, 0 on error
 *
 * \see RFC2440bis-12 5.2.3
 */
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

    assert(subptag.length_read == subptag.length);  /* XXX: this should not be an assert but a parse error.  It's not
						       our fault if the packet is inconsistent with itself. */

    ptag->length_read+=subptag.length_read;

    return 1;
    }

/** Parse a version 4 signature.
 *
 * This function parses a version 4 signature including all its hashed and unhashed subpackets.
 *
 * Once the signature packet has been parsed successfully, it is passed to the callback.
 *
 * \param *ptag		Pointer to the Packet Tag.
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		1 on success, 0 on error
 *
 * \see RFC2440bis-12 5.2.3
 */
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

/** Parse a signature subpacket.
 *
 * This function calls the appropriate function to handle v3 or v4 signatures.
 *
 * Once the signature packet has been parsed successfully, it is passed to the callback.
 *
 * \param *ptag		Pointer to the Packet Tag.
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		1 on success, 0 on error
 */
static int parse_signature(ops_ptag_t *ptag,ops_packet_reader_t *reader,
			   ops_packet_parse_callback_t *cb,
			   ops_parse_packet_options_t *opt)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    if(!limited_read(c,1,ptag,reader,cb))
	return 0;

    /* XXX: More V2 issues!  - Ben*/
    /* XXX: are there v2 signatures? - Peter */
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
    case OPS_PTAG_CT_PUBLIC_SUBKEY:
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

    if(tag == OPS_PTAG_SS_ALL)
	{
	int n;

	for(n=0 ; n < 256 ; ++n)
	    ops_parse_packet_options(opt,OPS_PTAG_SIGNATURE_SUBPACKET_BASE+n,
				     type);
	return;
	}

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


/* vim:set textwidth=120: */
/* vim:set ts=8: */
