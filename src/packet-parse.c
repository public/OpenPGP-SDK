/** \file packet-parse.c
 * Parser for OpenPGP packets.
 *
 * $Id$
 */

#include "packet.h"
#include "packet-parse.h"
#include "util.h"
#include "compress.h"
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef DMALLOC
# include <dmalloc.h>
#endif
 
static void init_subregion(ops_region_t *subregion,ops_region_t *region)
    {
    memset(subregion,'\0',sizeof *subregion);
    subregion->parent=region;
    }

#define CB(t,pc)	do { (pc)->tag=(t); if(opt->cb(pc,opt->cb_arg) == OPS_RELEASE_MEMORY) ops_parser_content_free(pc); } while(0)
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

static ops_reader_ret_t base_read(unsigned char *dest,unsigned *plength,
				  ops_reader_flags_t flags,
				  ops_parse_options_t *opt)
    {
    ops_reader_ret_t ret=opt->reader(dest,plength,flags,opt->reader_arg);
    if(ret != OPS_R_OK && ret != OPS_R_PARTIAL_READ)
	return ret;

    if(opt->accumulate)
	{
	assert(opt->asize >= opt->alength);
	if(opt->alength+*plength > opt->asize)
	    {
	    opt->asize=opt->asize*2+*plength;
	    opt->accumulated=realloc(opt->accumulated,opt->asize);
	    }
	assert(opt->asize >= opt->alength+*plength);
	memcpy(opt->accumulated+opt->alength,dest,*plength);
	}
    // we track length anyway, because it is used for packet offsets
    opt->alength+=*plength;

    return ret;
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
static ops_reader_ret_t read_scalar(unsigned *result,unsigned length,
				    ops_parse_options_t *opt)
    {
    unsigned t=0;
    ops_reader_ret_t ret;

    assert (length <= sizeof(*result));

    while(length--)
	{
	unsigned char c[1];
	unsigned one=1;

	ret=base_read(c,&one,0,opt);
	if(ret != OPS_R_OK)
	    return ret;
	t=(t << 8)+c[0];
	}
    *result=t;
    return OPS_R_OK;
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
int ops_limited_read(unsigned char *dest,unsigned length,
		     ops_region_t *region,ops_parse_options_t *opt)
    {
    ops_parser_content_t content;
    ops_reader_ret_t ret;

    if(!region->indeterminate && region->length_read+length > region->length)
	ERR("Not enough data left");

    ret=base_read(dest,&length,region->indeterminate ? OPS_RETURN_LENGTH : 0,
		  opt);

    if(ret != OPS_R_OK && ret != OPS_R_PARTIAL_READ)
	ERR("Read failed");

    region->last_read=length;
    do
	{
	region->length_read+=length;
	assert(!region->parent || region->length <= region->parent->length);
	}
    while((region=region->parent));

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
static int limited_skip(unsigned length,ops_region_t *region,
			ops_parse_options_t *opt)
    {
    unsigned char buf[8192];

    while(length)
	{
	int n=length%8192;
	if(!ops_limited_read(buf,n,region,opt))
	    return 0;
	length-=n;
	}
    return 1;
    }

/** Read a scalar.
 *
 * Read a Big Endian scalar of length bytes, respecting packet boundaries (by calling #limited_read to read the raw
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
			       ops_region_t *region,
			       ops_parse_options_t *opt)
    {
    unsigned char c[4];
    unsigned t;
    int n;

    if(!ops_limited_read(c,length,region,opt))
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
static int limited_read_time(time_t *dest,ops_region_t *region,
			     ops_parse_options_t *opt)
    {
    return limited_read_scalar((unsigned *)dest,4,region,opt);
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
static int limited_read_mpi(BIGNUM **pbn,ops_region_t *region,
			    ops_parse_options_t *opt)
    {
    unsigned length;
    unsigned nonzero;
    unsigned char buf[8192]; /* an MPI has a 2 byte length part.  Length
                                is given in bits, so the largest we should
                                ever need for the buffer is 8192 bytes. */
    ops_parser_content_t content;

    if(!limited_read_scalar(&length,2,region,opt))
	return 0;

    nonzero=length&7; /* there should be this many zero bits in the MS byte */
    if(!nonzero)
	nonzero=8;
    length=(length+7)/8;

    assert(length <= 8192);
    if(!ops_limited_read(buf,length,region,opt))
	return 0;

    if((buf[0] >> nonzero) != 0 || !(buf[0]&(1 << (nonzero-1))))
	ERR("MPI format error");  /* XXX: Ben, one part of this constraint does not apply to encrypted MPIs the draft says. -- peter */

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
static int limited_read_new_length(unsigned *length,ops_region_t *region,
				   ops_parse_options_t *opt)
    {
    unsigned char c[1];

    if(!ops_limited_read(c,1,region,opt))
	return 0;
    if(c[0] < 192)
	{
	*length=c[0];
	return 1;
	}
    if(c[0] < 255)
	{
	unsigned t=(c[0]-192) << 8;

	if(!ops_limited_read(c,1,region,opt))
	    return 0;
	*length=t+c[1]+192;
	return 1;
	}
    return limited_read_scalar(length,4,region,opt);
    }

void ops_packet_free(ops_packet_t *packet)
    {
    free(packet->raw);
    packet->raw=NULL;
    }

void ops_parser_content_free(ops_parser_content_t *c)
    {
    switch(c->tag)
	{
    case OPS_PARSER_PTAG:
    case OPS_PTAG_CT_COMPRESSED:
    case OPS_PTAG_SS_CREATION_TIME:
    case OPS_PTAG_SS_EXPIRATION_TIME:
    case OPS_PTAG_SS_TRUST:
    case OPS_PTAG_SS_ISSUER_KEY_ID:
    case OPS_PTAG_CT_ONE_PASS_SIGNATURE:
    case OPS_PTAG_SS_PRIMARY_USER_ID:
    case OPS_PTAG_SS_REVOCABLE:
    case OPS_PTAG_SS_REVOCATION_KEY:
	break;

    case OPS_PTAG_CT_TRUST:
	ops_trust_free(&c->content.trust);
	break;

    case OPS_PTAG_CT_SIGNATURE:
	ops_signature_free(&c->content.signature);
	break;

    case OPS_PTAG_CT_PUBLIC_KEY:
    case OPS_PTAG_CT_PUBLIC_SUBKEY:
	ops_public_key_free(&c->content.public_key);
	break;

    case OPS_PTAG_CT_USER_ID:
	ops_user_id_free(&c->content.user_id);
	break;

    case OPS_PTAG_SS_PREFERRED_SKA:
	ops_ss_preferred_ska_free(&c->content.ss_preferred_ska);
	break;

    case OPS_PTAG_SS_PREFERRED_HASH:
	ops_ss_preferred_hash_free(&c->content.ss_preferred_hash);
	break;

    case OPS_PTAG_SS_PREFERRED_COMPRESSION:
	ops_ss_preferred_compression_free(&c->content.ss_preferred_compression);
	break;

    case OPS_PTAG_SS_KEY_FLAGS:
	ops_ss_key_flags_free(&c->content.ss_key_flags);
	break;

    case OPS_PTAG_SS_FEATURES:
	ops_ss_key_flags_free(&c->content.ss_key_flags);
	break;

    case OPS_PARSER_PACKET_END:
	ops_packet_free(&c->content.packet);
	break;

    case OPS_PARSER_ERROR:
	break;

    default:
	fprintf(stderr,"Can't free %d (0x%x)\n",c->tag,c->tag);
	assert(0);
	}
    }

static void free_BN(BIGNUM **pp)
    {
    BN_free(*pp);
    *pp=NULL;
    }

void ops_public_key_free(ops_public_key_t *p)
    {
    switch(p->algorithm)
	{
    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:
	free_BN(&p->key.rsa.n);
	free_BN(&p->key.rsa.e);
	break;

    case OPS_PKA_DSA:
	free_BN(&p->key.dsa.p);
	free_BN(&p->key.dsa.q);
	free_BN(&p->key.dsa.g);
	free_BN(&p->key.dsa.y);
	break;

    case OPS_PKA_ELGAMAL:
	free_BN(&p->key.elgamal.p);
	free_BN(&p->key.elgamal.g);
	free_BN(&p->key.elgamal.y);
	break;

    default:
	assert(0);
	}
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
static int parse_public_key(ops_content_tag_t tag,ops_region_t *region,
			    ops_parse_options_t *opt)
    {
    ops_parser_content_t content;
    unsigned char c[1];

    assert (region->length_read == 0);  /* We should not have read anything so far */

    if(!ops_limited_read(c,1,region,opt))
	return 0;
    C.public_key.version=c[0];
    if(C.public_key.version < 2 || C.public_key.version > 4)
	ERR1("Bad public key version (0x%02x)",C.public_key.version);

    if(!limited_read_time(&C.public_key.creation_time,region,opt))
	return 0;

    C.public_key.days_valid=0;
    if((C.public_key.version == 2 || C.public_key.version == 3)
       && !limited_read_scalar(&C.public_key.days_valid,2,region,opt))
	return 0;

    if(!ops_limited_read(c,1,region,opt))
	return 0;

    C.public_key.algorithm=c[0];

    switch(C.public_key.algorithm)
	{
    case OPS_PKA_DSA:
	if(!limited_read_mpi(&C.public_key.key.dsa.p,region,opt)
	   || !limited_read_mpi(&C.public_key.key.dsa.q,region,opt)
	   || !limited_read_mpi(&C.public_key.key.dsa.g,region,opt)
	   || !limited_read_mpi(&C.public_key.key.dsa.y,region,opt))
	    return 0;
	break;

    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:
	if(!limited_read_mpi(&C.public_key.key.rsa.n,region,opt)
	   || !limited_read_mpi(&C.public_key.key.rsa.e,region,opt))
	    return 0;
	break;

    case OPS_PKA_ELGAMAL:
	if(!limited_read_mpi(&C.public_key.key.elgamal.p,region,opt)
	   || !limited_read_mpi(&C.public_key.key.elgamal.g,region,opt)
	   || !limited_read_mpi(&C.public_key.key.elgamal.y,region,opt))
	    return 0;
	break;

    default:
	ERR1("Unknown public key algorithm (%d)",C.public_key.algorithm);
	}

    if(region->length_read != region->length)
	ERR1("Unconsumed data (%d)", region->length-region->length_read);

    CB(tag,&content);

    return 1;
    }

void ops_user_id_free(ops_user_id_t *id)
    {
    free(id->user_id);
    id->user_id=NULL;
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
static int parse_user_id(ops_region_t *region,ops_parse_options_t *opt)
    {
    ops_parser_content_t content;

    assert (region->length_read == 0);  /* We should not have read anything so far */

    assert(region->length);
    C.user_id.user_id=malloc(region->length+1);  /* XXX should we not like check malloc's return value? */
    if(!ops_limited_read(C.user_id.user_id,region->length,region,opt))
	return 0;
    C.user_id.user_id[region->length] = 0; /* terminate the string */

    CB(OPS_PTAG_CT_USER_ID,&content);

    return 1;
    }

void ops_signature_free(ops_signature_t *sig)
    {
    switch(sig->key_algorithm)
	{
    case OPS_PKA_RSA:
	free_BN(&sig->signature.rsa.sig);
	break;

    case OPS_PKA_DSA:
	free_BN(&sig->signature.dsa.r);
	free_BN(&sig->signature.dsa.s);
	break;

    default:
	assert(0);
	}
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
static int parse_v3_signature(ops_region_t *region,ops_parse_options_t *opt)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    C.signature.version=OPS_SIG_V3;

    /* hash info length */
    if(!ops_limited_read(c,1,region,opt))
	return 0;
    if(c[0] != 5)
	ERR("bad hash info length");

    if(!ops_limited_read(c,1,region,opt))
	return 0;
    C.signature.type=c[0];
    /* XXX: check signature type */

    if(!limited_read_time(&C.signature.creation_time,region,opt))
	return 0;

    if(!ops_limited_read(C.signature.signer_id,8,region,opt))
	return 0;

    if(!ops_limited_read(c,1,region,opt))
	return 0;
    C.signature.key_algorithm=c[0];
    /* XXX: check algorithm */

    if(!ops_limited_read(c,1,region,opt))
	return 0;
    C.signature.hash_algorithm=c[0];
    /* XXX: check algorithm */
    
    if(!ops_limited_read(C.signature.hash2,2,region,opt))
	return 0;

    switch(C.signature.key_algorithm)
	{
    case OPS_PKA_RSA:
	if(!limited_read_mpi(&C.signature.signature.rsa.sig,region,opt))
	    return 0;
	break;

    case OPS_PKA_DSA:
	if(!limited_read_mpi(&C.signature.signature.dsa.r,region,opt)
	   || !limited_read_mpi(&C.signature.signature.dsa.s,region,opt))
	    return 0;
	break;

    default:
	ERR1("Bad signature key algorithm (%d)",C.signature.key_algorithm);
	}

    if(region->length_read != region->length)
	ERR1("Unconsumed data (%d)",region->length-region->length_read);

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
static int parse_one_signature_subpacket(ops_signature_t *sig,
					 ops_region_t *region,
					 ops_parse_options_t *opt)
    {
    ops_region_t subregion;
    char c[1];
    ops_parser_content_t content;
    unsigned t8,t7;
    ops_boolean_t read=ops_true;
    unsigned char bool[1];

    init_subregion(&subregion,region);
    if(!limited_read_new_length(&subregion.length,region,opt))
	return 0;

    if(!ops_limited_read(c,1,&subregion,opt))
	return 0;

    t8=(c[0]&0x7f)/8;
    t7=1 << (c[0]&7);

    content.critical=c[0] >> 7;
    content.tag=OPS_PTAG_SIGNATURE_SUBPACKET_BASE+(c[0]&0x7f);

    /* Application wants it delivered raw */
    if(opt->ss_raw[t8]&t7)
	{
	C.ss_raw.tag=content.tag;
	C.ss_raw.length=subregion.length-1;
	C.ss_raw.raw=malloc(C.ss_raw.length);
	if(!ops_limited_read(C.ss_raw.raw,C.ss_raw.length,&subregion,opt))
	    return 0;
	CB(OPS_PTAG_RAW_SS,&content);
	return 1;
	}

    switch(content.tag)
	{
    case OPS_PTAG_SS_CREATION_TIME:
    case OPS_PTAG_SS_EXPIRATION_TIME:
	if(!limited_read_time(&C.ss_time.time,&subregion,opt))
	    return 0;
	break;

    case OPS_PTAG_SS_TRUST:
	if(!ops_limited_read(&C.ss_trust.level,1,&subregion,opt)
	   || !ops_limited_read(&C.ss_trust.amount,1,&subregion,opt))
	    return 0;
	break;

    case OPS_PTAG_SS_REVOCABLE:
	if (!ops_limited_read (bool, 1, &subregion, opt))
	    return 0;
	C.ss_revocable.revocable = !!bool;
	break;

    case OPS_PTAG_SS_ISSUER_KEY_ID:
	if(!ops_limited_read(C.ss_issuer_key_id.key_id,OPS_KEY_ID_SIZE,
			     &subregion,opt))
	    return 0;
	memcpy(sig->signer_id,C.ss_issuer_key_id.key_id,OPS_KEY_ID_SIZE);
	break;

    case OPS_PTAG_SS_PREFERRED_SKA:

	C.ss_preferred_ska.len = subregion.length - subregion.length_read;
	C.ss_preferred_ska.data = malloc(C.ss_preferred_ska.len);

	if (!ops_limited_read(C.ss_preferred_ska.data,
			      C.ss_preferred_ska.len, &subregion, opt))
	    return 0;
	break;
			    	
    case OPS_PTAG_SS_PREFERRED_HASH:

	C.ss_preferred_hash.len = subregion.length - subregion.length_read;
	C.ss_preferred_hash.data = malloc(C.ss_preferred_hash.len);

	if (!ops_limited_read(C.ss_preferred_hash.data,
			      C.ss_preferred_hash.len, &subregion, opt))
	    return 0;
	break;
			    	
    case OPS_PTAG_SS_PREFERRED_COMPRESSION:

	C.ss_preferred_compression.len = subregion.length - subregion.length_read;
	C.ss_preferred_compression.data = malloc(C.ss_preferred_compression.len);

	if (!ops_limited_read(C.ss_preferred_compression.data,
			      C.ss_preferred_compression.len, &subregion, opt))
	    return 0;
	break;
			    	
    case OPS_PTAG_SS_PRIMARY_USER_ID:
	if (!ops_limited_read (bool, 1, &subregion, opt))
	    return 0;
	C.ss_primary_user_id.primary_user_id = !!bool;
	break;
 
    case OPS_PTAG_SS_KEY_FLAGS:
	C.ss_key_flags.len = subregion.length - subregion.length_read;
	C.ss_key_flags.data = malloc(C.ss_key_flags.len);
	if (!ops_limited_read(C.ss_key_flags.data,C.ss_key_flags.len,
			      &subregion,opt))
	    return 0;
	break;

    case OPS_PTAG_SS_FEATURES:
	C.ss_features.len = subregion.length - subregion.length_read;
	C.ss_features.data = malloc(C.ss_features.len);
	if (!ops_limited_read(C.ss_features.data,C.ss_features.len,
			      &subregion,opt))
	    return 0;
	break;

    case OPS_PTAG_SS_REVOCATION_KEY:
 
	/* octet 0 = class. Bit 0x80 must be set */
	if (!ops_limited_read (&C.ss_revocation_key.class, 1, &subregion, opt))
	    return 0;
	if (!(C.ss_revocation_key.class & 0x80))
	    {
	    printf
		("Warning: OPS_PTAG_SS_REVOCATION_KEY class: Bit 0x80 should be set\n");
	    return 0;
	    }
 
	/* octet 1 = algid */
	if (!ops_limited_read (&C.ss_revocation_key.algid, 1, &subregion, opt))
	    return 0;
 
	/* octets 2-21 = fingerprint */
	if (!ops_limited_read
	    (&C.ss_revocation_key.fingerprint[0], 20, &subregion,
	     opt))
	    return 0;
	break;
 
    default:
	if(opt->ss_parsed[t8]&t7)
	    ERR1("Unknown signature subpacket type (%d)",c[0]&0x7f);
	read=ops_false;
	break;
	}

    /* Application doesn't want it delivered parsed */
    if(!(opt->ss_parsed[t8]&t7))
	{
	if(content.critical)
	    ERR1("Critical signature subpacket ignored (%d)",c[0]&0x7f);
	if(!read && !limited_skip(subregion.length-1,&subregion,opt))
	    return 0;
	//	printf("skipped %d length %d\n",c[0]&0x7f,subregion.length);
	if(read)
	    ops_parser_content_free(&content);
	return 1;
	}

    if(read && subregion.length_read != subregion.length)
	ERR1("Unconsumed data (%d)", subregion.length-subregion.length_read);
 
    CB(content.tag,&content);

    return 1;
    }

/** ops_ss_preferred_ska_free(ops_ss_preferred_ska_t * ss_preferred_ska)
 */

void ops_ss_preferred_ska_free(ops_ss_preferred_ska_t * ss_preferred_ska)
    {
    free(ss_preferred_ska->data);
    ss_preferred_ska->data=NULL;
    ss_preferred_ska->len=0;
    }

/** ops_ss_preferred_hash_free(ops_ss_preferred_hash_t * ss_preferred_hash)
 */

void ops_ss_preferred_hash_free(ops_ss_preferred_hash_t * ss_preferred_hash)
    {
    free(ss_preferred_hash->data);
    ss_preferred_hash->data=NULL;
    ss_preferred_hash->len=0;
    }

/** ops_ss_preferred_compression_free(ops_ss_preferred_compression_t * ss_preferred_compression)
 */

void ops_ss_preferred_compression_free(ops_ss_preferred_compression_t * ss_preferred_compression)
    {
    free(ss_preferred_compression->data);
    ss_preferred_compression->data=NULL;
    ss_preferred_compression->len=0;
    }

void ops_ss_key_flags_free(ops_ss_key_flags_t * ss_key_flags)
    {
    free(ss_key_flags->data);
    ss_key_flags->data=NULL;
    ss_key_flags->len=0;
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
static int parse_signature_subpackets(ops_signature_t *sig,
				      ops_region_t *region,
				      ops_parse_options_t *opt)
    {
    ops_region_t subregion;

    init_subregion(&subregion,region);
    if(!limited_read_scalar(&subregion.length,2,region,opt))
	return 0;

    while(subregion.length_read < subregion.length)
	if(!parse_one_signature_subpacket(sig,&subregion,opt))
	    return 0;

    assert(subregion.length_read == subregion.length);  /* XXX: this should not be an assert but a parse error.  It's not
							   our fault if the packet is inconsistent with itself. */

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
static int parse_v4_signature(ops_region_t *region,ops_parse_options_t *opt,
			      size_t v4_hashed_data_start)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    C.signature.version=OPS_SIG_V4;
    C.signature.v4_hashed_data_start=v4_hashed_data_start;

    if(!ops_limited_read(c,1,region,opt))
	return 0;
    C.signature.type=c[0];
    /* XXX: check signature type */

    if(!ops_limited_read(c,1,region,opt))
	return 0;
    C.signature.key_algorithm=c[0];
    /* XXX: check algorithm */

    if(!ops_limited_read(c,1,region,opt))
	return 0;
    C.signature.hash_algorithm=c[0];
    /* XXX: check algorithm */

    if(!parse_signature_subpackets(&C.signature,region,opt))
	return 0;
    C.signature.v4_hashed_data_length=opt->alength
	-C.signature.v4_hashed_data_start;

    if(!parse_signature_subpackets(&C.signature,region,opt))
	return 0;

    if(!ops_limited_read(C.signature.hash2,2,region,opt))
	return 0;

    switch(C.signature.key_algorithm)
	{
    case OPS_PKA_RSA:
	if(!limited_read_mpi(&C.signature.signature.rsa.sig,region,opt))
	    return 0;
	break;

    case OPS_PKA_DSA:
	if(!limited_read_mpi(&C.signature.signature.dsa.r,region,opt)
	   || !limited_read_mpi(&C.signature.signature.dsa.s,region,opt))
	    return 0;
	break;

    default:
	ERR1("Bad signature key algorithm (%d)",C.signature.key_algorithm);
	}

    if(region->length_read != region->length)
	ERR1("Unconsumed data (%d)",region->length-region->length_read);

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
static int parse_signature(ops_region_t *region,ops_parse_options_t *opt)
    {
    unsigned char c[1];
    ops_parser_content_t content;
    size_t v4_hashed_data_start;

    assert(region->length_read == 0);  /* We should not have read anything so far */

    memset(&content,'\0',sizeof content);

    v4_hashed_data_start=opt->alength;
    if(!ops_limited_read(c,1,region,opt))
	return 0;

    /* XXX: More V2 issues!  - Ben*/
    /* XXX: are there v2 signatures? - Peter */
    if(c[0] == 2 || c[0] == 3)
	return parse_v3_signature(region,opt);
    else if(c[0] == 4)
	return parse_v4_signature(region,opt,v4_hashed_data_start);
    ERR1("Bad signature version (%d)",c[0]);
    }

static int parse_compressed(ops_region_t *region,ops_parse_options_t *opt)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    if(!ops_limited_read(c,1,region,opt))
	return 0;

    C.compressed.type=c[0];

    CB(OPS_PTAG_CT_COMPRESSED,&content);

    /* The content of a compressed data packet is more OpenPGP packets
       once decmppressed, so recursively handle them */

    return ops_decompress(region,opt);
    }

static int parse_one_pass(ops_region_t *region,ops_parse_options_t *opt)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    if(!ops_limited_read(&C.one_pass_signature.version,1,region,opt))
	return 0;
    if(C.one_pass_signature.version != 3)
	ERR1("Bad one-pass signature version (%d)",
	     C.one_pass_signature.version);

    if(!ops_limited_read(c,1,region,opt))
	return 0;
    C.one_pass_signature.sig_type=c[0];

    if(!ops_limited_read(c,1,region,opt))
	return 0;
    C.one_pass_signature.hash_algorithm=c[0];

    if(!ops_limited_read(c,1,region,opt))
	return 0;
    C.one_pass_signature.key_algorithm=c[0];

    if(!ops_limited_read(C.one_pass_signature.keyid,
			 sizeof C.one_pass_signature.keyid,region,opt))
	return 0;

    if(!ops_limited_read(c,1,region,opt))
	return 0;
    C.one_pass_signature.nested=!!c[0];

    CB(OPS_PTAG_CT_ONE_PASS_SIGNATURE,&content);

    return 1;
    }

void ops_trust_free(ops_trust_t * trust)
    {
    free(trust->data);
    trust->data=NULL;
    trust->len=0;
    }

static int
parse_trust (ops_region_t * region, ops_parse_options_t * opt)
    {
    ops_parser_content_t content;

    C.trust.len = region->length - region->length_read;
    C.trust.data = malloc(C.trust.len);
	
    if (!ops_limited_read (C.trust.data, C.trust.len, 
			   region, opt))
	return 0;

    CB (OPS_PTAG_CT_TRUST, &content);

    return 1;
    }

/** Parse one packet.
 *
 * This function parses the packet tag.  It computes the value of the content tag and then calls the appropriate
 * function to handle the content.
 *
 * \param *reader	Our reader
 * \param *cb		The callback
 * \param *opt		Parsing options
 * \return		1 on success, 0 on error
 */
static int ops_parse_one_packet(ops_parse_options_t *opt)
    {
    char ptag[1];
    ops_reader_ret_t ret;
    ops_parser_content_t content;
    int r;
    ops_region_t region;
    unsigned one=1;
    ops_boolean_t indeterminate=ops_false;

    ret=base_read(ptag,&one,0,opt);
    if(ret == OPS_R_EOF)
	return 0;

    assert(ret == OPS_R_OK);
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
	C.ptag.length_type=*ptag&OPS_PTAG_OF_LENGTH_TYPE_MASK;
	switch(C.ptag.length_type)
	    {
	case OPS_PTAG_OF_LT_ONE_BYTE:
	    ret=read_scalar(&C.ptag.length,1,opt);
	    assert(ret == OPS_R_OK);
	    break;

	case OPS_PTAG_OF_LT_TWO_BYTE:
	    ret=read_scalar(&C.ptag.length,2,opt);
	    assert(ret == OPS_R_OK);
	    break;

	case OPS_PTAG_OF_LT_FOUR_BYTE:
	    ret=read_scalar(&C.ptag.length,4,opt);
	    assert(ret == OPS_R_OK);
	    break;

	case OPS_PTAG_OF_LT_INDETERMINATE:
	    C.ptag.length=0;
	    indeterminate=ops_true;
	    break;
	    }
	}

    CB(OPS_PARSER_PTAG,&content);

    init_subregion(&region,NULL);
    region.length=C.ptag.length;
    region.indeterminate=indeterminate;
    switch(C.ptag.content_tag)
	{
    case OPS_PTAG_CT_SIGNATURE:
	r=parse_signature(&region,opt);
	break;

    case OPS_PTAG_CT_PUBLIC_KEY:
    case OPS_PTAG_CT_PUBLIC_SUBKEY:
	r=parse_public_key(C.ptag.content_tag,&region,opt);
	break;

    case OPS_PTAG_CT_TRUST:
	r = parse_trust(&region, opt);
	break;
      
    case OPS_PTAG_CT_USER_ID:
	r=parse_user_id(&region,opt);
	break;

    case OPS_PTAG_CT_COMPRESSED:
	r=parse_compressed(&region,opt);
	break;

    case OPS_PTAG_CT_ONE_PASS_SIGNATURE:
	r=parse_one_pass(&region,opt);
	break;

    default:
	format_error(&content,"Format error (unknown content tag %d)",
		     C.ptag.content_tag);
	CB(OPS_PARSER_ERROR,&content);
	r=0;
	}
    if(opt->accumulate)
	{
	C.packet.length=opt->alength;
	C.packet.raw=opt->accumulated;
	opt->accumulated=NULL;
	opt->asize=0;
	CB(OPS_PARSER_PACKET_END,&content);
	}
    opt->alength=0;
	
    return r ? 1 : -1;
    }

/** Parse packets.
 *
 * Parses packets calling #ops_parse_one_packet until an error occurs or until EOF (which is just another error anyway).
 *
 * \param *reader	Our reader
 * \param *cb		The callback
 * \param *opt		Parsing options
 * \return		1 on success, 0 on error
 */
int ops_parse(ops_parse_options_t *opt)
    {
    int r;

    while((r=ops_parse_one_packet(opt)) > 0)
	;

    return r == 0;
    }

/* XXX: Make all packet types optional, not just subpackets */
void ops_parse_options(ops_parse_options_t *opt,
		       ops_content_tag_t tag,
		       ops_parse_type_t type)
    {
    int t8,t7;

    if(tag == OPS_PTAG_SS_ALL)
	{
	int n;

	for(n=0 ; n < 256 ; ++n)
	    ops_parse_options(opt,OPS_PTAG_SIGNATURE_SUBPACKET_BASE+n,
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
