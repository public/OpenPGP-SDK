/** \file
 * \brief Parser for OpenPGP packets
 */

#include <openpgpsdk/packet.h>
#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/util.h>
#include <openpgpsdk/compress.h>
#include <openpgpsdk/errors.h>
#include "parse_local.h"

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/**
 * limited_read_data reads the specified amount of the subregion's data 
 * into a data_t structure
 *
 * \param data	Empty structure which will be filled with data
 * \param len	Number of octets to read
 * \param subregion
 * \param parse_info	How to parse
 *
 * \return 1 on success, 0 on failure
 */
static int limited_read_data(ops_data_t *data,unsigned int len,
			     ops_region_t *subregion,ops_parse_info_t *parse_info)
    {
    data->len = len;

    assert(subregion->length-subregion->length_read >= len);

    data->contents=malloc(data->len);
    if (!data->contents)
	return 0;

    if (!ops_limited_read(data->contents, data->len,subregion,
			  &parse_info->errors,&parse_info->rinfo,
			  &parse_info->cbinfo))
	return 0;
    
    return 1;
    }

/**
 * read_data reads the remainder of the subregion's data 
 * into a data_t structure
 *
 * \param data
 * \param subregion
 * \param parse_info
 * 
 * \return 1 on success, 0 on failure
 */
static int read_data(ops_data_t *data,ops_region_t *subregion,
		     ops_parse_info_t *parse_info)
    {
    int len;

    len=subregion->length-subregion->length_read;

    return(limited_read_data(data,len,subregion,parse_info));
    }

/**
 * Reads the remainder of the subregion as a string.
 * It is the user's responsibility to free the memory allocated here.
 */

static int read_unsigned_string(unsigned char **str,ops_region_t *subregion,
				ops_parse_info_t *pinfo)
    {
    int len=0;

    len=subregion->length-subregion->length_read;

    *str=malloc(len+1);
    if(!(*str))
	return 0;

    if(len && !ops_limited_read(*str,len,subregion,&pinfo->errors,
				&pinfo->rinfo,&pinfo->cbinfo))
	return 0;

    /*! ensure the string is NULL-terminated */

    (*str)[len]=(char) NULL;

    return 1;
    }

static int read_string(char **str, ops_region_t *subregion, ops_parse_info_t *parse_info)
    {
    return (read_unsigned_string((unsigned char **)str, subregion, parse_info));
    }

void ops_init_subregion(ops_region_t *subregion,ops_region_t *region)
    {
    memset(subregion,'\0',sizeof *subregion);
    subregion->parent=region;
    }

/*! \todo descr for CB macro */
/*! \todo check other callback functions to check they match this usage */
#define CB(cbinfo,t,pc)	do { (pc)->tag=(t); if((cbinfo)->cb(pc,(cbinfo)) == OPS_RELEASE_MEMORY) ops_parser_content_free(pc); } while(0)
#define CBP(info,t,pc) CB(&(info)->cbinfo,t,pc)
/*! macro to save typing */
#define C		content.content
/*! set error code in content and run CallBack to handle error */
#define ERRCODE(cbinfo,err)	do { C.errcode.errcode=err; CB(cbinfo,OPS_PARSER_ERRCODE,&content); } while(0)
#define ERRCODEP(pinfo,err)	do { C.errcode.errcode=err; CBP(pinfo,OPS_PARSER_ERRCODE,&content); } while(0)
/*! set error text in content and run CallBack to handle error, then return */
#define ERR(cbinfo,err)	do { C.error.error=err; CB(cbinfo,OPS_PARSER_ERROR,&content); return ops_false; } while(0)
#define ERRP(info,err)	do { C.error.error=err; CBP(info,OPS_PARSER_ERROR,&content); return ops_false; } while(0)
/*! set error text in content and run CallBack to handle warning, do not return */
#define WARN(warn)	do { C.error.error=warn; CB(OPS_PARSER_ERROR,&content);; } while(0)
#define WARNP(info,warn)	do { C.error.error=warn; CBP(info,OPS_PARSER_ERROR,&content); } while(0)
/*! \todo descr ERR1 macro */
#define ERR1P(info,fmt,x)	do { format_error(&content,(fmt),(x)); CBP(info,OPS_PARSER_ERROR,&content); return ops_false; } while(0)

/* XXX: replace ops_ptag_t with something more appropriate for limiting
   reads */

/* Note that this makes the parser non-reentrant, in a limited way */
/* It is the caller's responsibility to avoid overflow in the buffer */
static void format_error(ops_parser_content_t *content,
			 const char *const fmt,...)
    {
    va_list va;
    static char buf[8192];

    va_start(va,fmt);
    vsnprintf(buf,sizeof buf,fmt,va);
    va_end(va);
    content->content.error.error=buf;
    }

/**
 * low-level function to read data from reader function
 *
 * Use this function, rather than calling the reader directly.
 *
 * If the accumulate flag is set in *parse_info, the function
 * adds the read data to the accumulated data, and updates 
 * the accumulated length. This is useful if, for example, 
 * the application wants access to the raw data as well as the
 * parsed data.
 *
 * \param *dest
 * \param *plength
 * \param flags
 * \param *parse_info
 *
 * \return OPS_R_OK
 * \return OPS_R_PARTIAL_READ
 * \return OPS_R_EOF
 * \return OPS_R_EARLY_EOF
 * 
 * \sa #ops_reader_ret_t, ops_reader_fd() for details of return codes
 */

static ops_reader_ret_t sub_base_read(unsigned char *dest,unsigned *plength,
				      ops_reader_flags_t flags,
				      ops_error_t **errors,
				      ops_reader_info_t *rinfo,
				      ops_parse_cb_info_t *cbinfo)
    {
    ops_reader_ret_t ret=rinfo->reader(dest,plength,flags,errors,rinfo,cbinfo);

    if(ret != OPS_R_OK && ret != OPS_R_PARTIAL_READ)
	return ret;

    if(rinfo->accumulate)
	{
	assert(rinfo->asize >= rinfo->alength);
	if(rinfo->alength+*plength > rinfo->asize)
	    {
	    rinfo->asize=rinfo->asize*2+*plength;
	    rinfo->accumulated=realloc(rinfo->accumulated,rinfo->asize);
	    }
	assert(rinfo->asize >= rinfo->alength+*plength);
	memcpy(rinfo->accumulated+rinfo->alength,dest,*plength);
	}
    // we track length anyway, because it is used for packet offsets
    rinfo->alength+=*plength;
    // and also the position
    rinfo->position+=*plength;

    return ret;
    }

ops_reader_ret_t ops_stacked_read(unsigned char *dest,unsigned *length,
				  ops_reader_flags_t flags,
				  ops_error_t **errors,
				  ops_reader_info_t *rinfo,
				  ops_parse_cb_info_t *cbinfo)
    { return sub_base_read(dest,length,flags,errors,rinfo->next,cbinfo); }

static ops_reader_ret_t base_read(unsigned char *dest,unsigned *plength,
				  ops_reader_flags_t flags,
				  ops_parse_info_t *info)
    {
    return sub_base_read(dest,plength,flags,&info->errors,&info->rinfo,
			 &info->cbinfo);
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
 * \return		OPS_R_OK on success, reader's return value otherwise
 *
 * \sa #ops_reader_ret_t for possible return codes
 */
static ops_reader_ret_t read_scalar(unsigned *result,unsigned length,
				    ops_parse_info_t *parse_info)
    {
    unsigned t=0;
    ops_reader_ret_t ret;

    assert (length <= sizeof(*result));

    while(length--)
	{
	unsigned char c[1];
	unsigned one=1;

	ret=base_read(c,&one,0,parse_info);
	if(ret != OPS_R_OK)
	    return ret;
	t=(t << 8)+c[0];
	}
    *result=t;
    return OPS_R_OK;
    }

/** Read bytes from a region within the packet.
 *
 * Read length bytes into the buffer pointed to by *dest.  Make sure
 * we do not read over the packet boundary.  Updates the Packet Tag's
 * ops_ptag_t::length_read.
 *
 * If length would make us read over the packet boundary, or if
 * reading fails, we call the callback with an OPS_PARSER_ERROR.
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param *dest		The destination buffer
 * \param length	How many bytes to read
 * \param *region	Pointer to packet region
 * \param *parse_info	How to parse, including callback function
 * \return		1 on success, 0 on error
 */
ops_boolean_t ops_limited_read(unsigned char *dest,unsigned length,
			       ops_region_t *region,ops_error_t **errors,
			       ops_reader_info_t *rinfo,
			       ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_t content;
    ops_reader_ret_t ret;

    if(!region->indeterminate && region->length_read+length > region->length)
	{
	ERRCODE(cbinfo,OPS_E_P_NOT_ENOUGH_DATA);
	return 0;
	}

    ret=sub_base_read(dest,&length,
		      region->indeterminate ? OPS_RETURN_LENGTH : 0,errors,
		      rinfo,cbinfo);

    if(ret != OPS_R_OK && ret != OPS_R_PARTIAL_READ)
	{
	ERRCODE(cbinfo,OPS_E_R_READ_FAILED);
	return 0;
	}

    region->last_read=length;
    do
	{
	region->length_read+=length;
	assert(!region->parent || region->length <= region->parent->length);
	}
    while((region=region->parent));

    return 1;
    }

ops_boolean_t ops_stacked_limited_read(unsigned char *dest,unsigned length,
				       ops_region_t *region,
				       ops_error_t **errors,
				       ops_reader_info_t *rinfo,
				       ops_parse_cb_info_t *cbinfo)
    { return ops_limited_read(dest,length,region,errors,rinfo->next,cbinfo); }

static ops_boolean_t limited_read(unsigned char *dest,unsigned length,
				  ops_region_t *region,ops_parse_info_t *info)
    {
    return ops_limited_read(dest,length,region,&info->errors,
			    &info->rinfo,&info->cbinfo);
    }

/** Skip over length bytes of this packet.
 *
 * Calls limited_read() to skip over some data.
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param length	How many bytes to skip
 * \param *region	Pointer to packet region
 * \param *parse_info	How to parse
 * \return		1 on success, 0 on error (calls the cb with OPS_PARSER_ERROR in limited_read()).
 */
static int limited_skip(unsigned length,ops_region_t *region,
			ops_parse_info_t *parse_info)
    {
    unsigned char buf[8192];

    while(length)
	{
	int n=length%8192;
	if(!limited_read(buf,n,region,parse_info))
	    return 0;
	length-=n;
	}
    return 1;
    }

/** Read a scalar.
 *
 * Read a big-endian scalar of length bytes, respecting packet
 * boundaries (by calling limited_read() to read the raw data).
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param *dest		The scalar value is stored here
 * \param length	How many bytes make up this scalar (at most 4)
 * \param *region	Pointer to current packet region
 * \param *parse_info	How to parse
 * \param *cb		The callback
 * \return		1 on success, 0 on error (calls the cb with OPS_PARSER_ERROR in limited_read()).
 *
 * \see RFC2440bis-12 3.1
 */
static int limited_read_scalar(unsigned *dest,unsigned length,
			       ops_region_t *region,
			       ops_parse_info_t *parse_info)
    {
    unsigned char c[4];
    unsigned t;
    unsigned n;

    assert(length <= 4);
    assert(sizeof(*dest) >= 4);
    if(!limited_read(c,length,region,parse_info))
	return 0;

    for(t=0,n=0 ; n < length ; ++n)
	t=(t << 8)+c[n];
    *dest=t;

    return 1;
    }

/** Read a scalar.
 *
 * Read a big-endian scalar of length bytes, respecting packet
 * boundaries (by calling limited_read() to read the raw data).
 *
 * The value read is stored in a size_t, which is a different size
 * from an unsigned on some platforms.
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param *dest		The scalar value is stored here
 * \param length	How many bytes make up this scalar (at most 4)
 * \param *region	Pointer to current packet region
 * \param *parse_info	How to parse
 * \param *cb		The callback
 * \return		1 on success, 0 on error (calls the cb with OPS_PARSER_ERROR in limited_read()).
 *
 * \see RFC2440bis-12 3.1
 */
static int limited_read_size_t_scalar(size_t *dest,unsigned length,
				      ops_region_t *region,
				      ops_parse_info_t *parse_info)
    {
    unsigned tmp;

    assert(sizeof(*dest) >= 4);

    /* Note that because the scalar is at most 4 bytes, we don't care
       if size_t is bigger than usigned */
    if(!limited_read_scalar(&tmp,length,region,parse_info))
	return 0;

    *dest=tmp;
    return 1;
    }

/** Read a timestamp.
 *
 * Timestamps in OpenPGP are unix time, i.e. seconds since The Epoch (1.1.1970).  They are stored in an unsigned scalar
 * of 4 bytes.
 *
 * This function reads the timestamp using limited_read_scalar().
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param *dest		The timestamp is stored here
 * \param *ptag		Pointer to current packet's Packet Tag.
 * \param *reader	Our reader
 * \param *cb		The callback
 * \return		see limited_read_scalar()
 *
 * \see RFC2440bis-12 3.5
 */
static int limited_read_time(time_t *dest,ops_region_t *region,
			     ops_parse_info_t *parse_info)
    {
    return limited_read_scalar((unsigned *)dest,4,region,parse_info);
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
 * \return		1 on success, 0 on error (by limited_read_scalar() or limited_read() or if the MPI is not properly formed (XXX
 * 				 see comment below - the callback is called with a OPS_PARSER_ERROR in case of an error)
 *
 * \see RFC2440bis-12 3.2
 */
static int limited_read_mpi(BIGNUM **pbn,ops_region_t *region,
			    ops_parse_info_t *parse_info)
    {
    unsigned length;
    unsigned nonzero;
    unsigned char buf[8192]; /* an MPI has a 2 byte length part.  Length
                                is given in bits, so the largest we should
                                ever need for the buffer is 8192 bytes. */
    ops_parser_content_t content;
    ops_boolean_t ret;

    parse_info->reading_mpi_length=ops_true;
    ret=limited_read_scalar(&length,2,region,parse_info);
    parse_info->reading_mpi_length=ops_false;
    if(!ret)
	return 0;

    nonzero=length&7; /* there should be this many zero bits in the MS byte */
    if(!nonzero)
	nonzero=8;
    length=(length+7)/8;

    assert(length <= 8192);
    if(!limited_read(buf,length,region,parse_info))
	return 0;

    if((buf[0] >> nonzero) != 0 || !(buf[0]&(1 << (nonzero-1))))
	{
	ERRCODEP(parse_info,OPS_E_P_MPI_FORMAT_ERROR);  /* XXX: Ben, one part of this constraint does not apply to encrypted MPIs the draft says. -- peter */
	return 0;
	}

    *pbn=BN_bin2bn(buf,length,NULL);
    return 1;
    }

/** Read some data with a New-Format length from reader.
 *
 * \sa Internet-Draft RFC2440bis-13.txt Section 4.2.2
 *
 * \param *length	Where the decoded length will be put
 * \param *parse_info	How to parse
 * \return		1 if OK, else 0
 *
 */

static int read_new_length(unsigned *length,ops_parse_info_t *parse_info)
    {
    unsigned char c[1];
    unsigned one=1;

    if(base_read(c,&one,0,parse_info) != OPS_R_OK)
	return 0;
    if(c[0] < 192)
	{
	*length=c[0];
	return 1;
	}
    if(c[0] < 255)
	{
	unsigned t=(c[0]-192) << 8;

	if(base_read(c,&one,0,parse_info) != OPS_R_OK)
	    return 0;
	*length=t+c[0]+192;
	return 1;
	}
    return (read_scalar(length,4,parse_info) == OPS_R_OK ? 1 : 0);
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
 * \return		1 on success, 0 on error (by limited_read_scalar() or limited_read() or if the MPI is not properly formed (XXX
 * 				 see comment below)
 *
 * \see RFC2440bis-12 4.2.2
 * \see ops_ptag_t
 */
static int limited_read_new_length(unsigned *length,ops_region_t *region,
				   ops_parse_info_t *parse_info)
    {
    unsigned char c[1];

    if(!limited_read(c,1,region,parse_info))
	return 0;
    if(c[0] < 192)
	{
	*length=c[0];
	return 1;
	}
    if(c[0] < 255)
	{
	unsigned t=(c[0]-192) << 8;

	if(!limited_read(c,1,region,parse_info))
	    return 0;
	*length=t+c[0]+192;
	return 1;
	}
    return limited_read_scalar(length,4,region,parse_info);
    }

static void data_free(ops_data_t *data)
    {
    free(data->contents);
    data->contents=NULL;
    data->len=0;
    }

static void string_free(char **str)
    {
    free(*str);
    *str=NULL;
    }

/*! Free packet memory, set pointer to NULL */
void ops_packet_free(ops_packet_t *packet)
    {
    free(packet->raw);
    packet->raw=NULL;
    }

void ops_headers_free(ops_headers_t *headers)
    {
    unsigned n;

    for(n=0 ; n < headers->nheaders ; ++n)
	{
	free(headers->headers[n].key);
	free(headers->headers[n].value);
	}
    free(headers->headers);
    headers->headers=NULL;
    }

void ops_signed_cleartext_trailer_free(ops_signed_cleartext_trailer_t *trailer)
    {
    free(trailer->hash);
    trailer->hash=NULL;
    }

void ops_cmd_get_passphrase_free(ops_secret_key_passphrase_t *skp)
    {
    free(skp->passphrase);
    skp->passphrase=NULL;
    }

/*! Free any memory allocated when parsing the packet content */
void ops_parser_content_free(ops_parser_content_t *c)
    {
    switch(c->tag)
	{
    case OPS_PARSER_PTAG:
    case OPS_PTAG_CT_COMPRESSED:
    case OPS_PTAG_SS_CREATION_TIME:
    case OPS_PTAG_SS_EXPIRATION_TIME:
    case OPS_PTAG_SS_KEY_EXPIRATION_TIME:
    case OPS_PTAG_SS_TRUST:
    case OPS_PTAG_SS_ISSUER_KEY_ID:
    case OPS_PTAG_CT_ONE_PASS_SIGNATURE:
    case OPS_PTAG_SS_PRIMARY_USER_ID:
    case OPS_PTAG_SS_REVOCABLE:
    case OPS_PTAG_SS_REVOCATION_KEY:
    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
    case OPS_PTAG_CT_LITERAL_DATA_BODY:
    case OPS_PTAG_CT_SIGNED_CLEARTEXT_BODY:
    case OPS_PTAG_CT_UNARMOURED_TEXT:
    case OPS_PTAG_CT_ARMOUR_TRAILER:
    case OPS_PTAG_CT_SIGNATURE_HEADER:
    case OPS_PTAG_CT_SE_DATA:
	break;

    case OPS_PTAG_CT_SIGNED_CLEARTEXT_HEADER:
	ops_headers_free(&c->content.signed_cleartext_header.headers);
	break;

    case OPS_PTAG_CT_ARMOUR_HEADER:
	ops_headers_free(&c->content.armour_header.headers);
	break;

    case OPS_PTAG_CT_SIGNED_CLEARTEXT_TRAILER:
	ops_signed_cleartext_trailer_free(&c->content.signed_cleartext_trailer);
	break;

    case OPS_PTAG_CT_TRUST:
	ops_trust_free(&c->content.trust);
	break;

    case OPS_PTAG_CT_SIGNATURE:
    case OPS_PTAG_CT_SIGNATURE_FOOTER:
	ops_signature_free(&c->content.signature);
	break;

    case OPS_PTAG_CT_PUBLIC_KEY:
    case OPS_PTAG_CT_PUBLIC_SUBKEY:
	ops_public_key_free(&c->content.public_key);
	break;

    case OPS_PTAG_CT_USER_ID:
	ops_user_id_free(&c->content.user_id);
	break;

    case OPS_PTAG_SS_SIGNERS_USER_ID:
	ops_user_id_free(&c->content.ss_signers_user_id);
	break;

    case OPS_PTAG_CT_USER_ATTRIBUTE:
	ops_user_attribute_free(&c->content.user_attribute);
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

    case OPS_PTAG_SS_KEY_SERVER_PREFS:
	ops_ss_key_server_prefs_free(&c->content.ss_key_server_prefs);
	break;

    case OPS_PTAG_SS_FEATURES:
	ops_ss_features_free(&c->content.ss_features);
	break;

    case OPS_PTAG_SS_NOTATION_DATA:
	ops_ss_notation_data_free(&c->content.ss_notation_data);
	break;

    case OPS_PTAG_SS_REGEXP:
	ops_ss_regexp_free(&c->content.ss_regexp);
	break;

    case OPS_PTAG_SS_POLICY_URL:
	ops_ss_policy_url_free(&c->content.ss_policy_url);
	break;

    case OPS_PTAG_SS_PREFERRED_KEY_SERVER:
	ops_ss_preferred_key_server_free(&c->content.ss_preferred_key_server);
	break;

    case OPS_PTAG_SS_USERDEFINED00:
    case OPS_PTAG_SS_USERDEFINED01:
    case OPS_PTAG_SS_USERDEFINED02:
    case OPS_PTAG_SS_USERDEFINED03:
    case OPS_PTAG_SS_USERDEFINED04:
    case OPS_PTAG_SS_USERDEFINED05:
    case OPS_PTAG_SS_USERDEFINED06:
    case OPS_PTAG_SS_USERDEFINED07:
    case OPS_PTAG_SS_USERDEFINED08:
    case OPS_PTAG_SS_USERDEFINED09:
    case OPS_PTAG_SS_USERDEFINED10:
	ops_ss_userdefined_free(&c->content.ss_userdefined);
	break;

    case OPS_PTAG_SS_RESERVED:
	ops_ss_reserved_free(&c->content.ss_unknown);
	break;

    case OPS_PTAG_SS_REVOCATION_REASON:
	ops_ss_revocation_reason_free(&c->content.ss_revocation_reason);
	break;

    case OPS_PARSER_PACKET_END:
	ops_packet_free(&c->content.packet);
	break;

    case OPS_PARSER_ERROR:
    case OPS_PARSER_ERRCODE:
	break;

    case OPS_PTAG_CT_SECRET_KEY:
    case OPS_PTAG_CT_ENCRYPTED_SECRET_KEY:
	ops_secret_key_free(&c->content.secret_key);
	break;

    case OPS_PTAG_CT_PK_SESSION_KEY:
	ops_pk_session_key_free(&c->content.pk_session_key);
	break;

    case OPS_PARSER_CMD_GET_SK_PASSPHRASE:
	ops_cmd_get_passphrase_free(&c->content.secret_key_passphrase);
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

void ops_pk_session_key_free(ops_pk_session_key_t *sk)
    {
    switch(sk->algorithm)
	{
    case OPS_PKA_RSA:
	free_BN(&sk->parameters.rsa.encrypted_m);
	break;

    case OPS_PKA_ELGAMAL:
	free_BN(&sk->parameters.elgamal.g_to_k);
	free_BN(&sk->parameters.elgamal.encrypted_m);
	break;

    default:
	assert(0);
	}
    }

/*! Free the memory used when parsing a public key */
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
    case OPS_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
	free_BN(&p->key.elgamal.p);
	free_BN(&p->key.elgamal.g);
	free_BN(&p->key.elgamal.y);
	break;

    default:
	assert(0);
	}
    }

static int parse_public_key_data(ops_public_key_t *key,ops_region_t *region,
				 ops_parse_info_t *parse_info)
    {
    ops_parser_content_t content;
    unsigned char c[1];

    assert (region->length_read == 0);  /* We should not have read anything so far */

    if(!limited_read(c,1,region,parse_info))
	return 0;
    key->version=c[0];
    if(key->version < 2 || key->version > 4)
	ERR1P(parse_info,"Bad public key version (0x%02x)",key->version);

    if(!limited_read_time(&key->creation_time,region,parse_info))
	return 0;

    key->days_valid=0;
    if((key->version == 2 || key->version == 3)
       && !limited_read_scalar(&key->days_valid,2,region,parse_info))
	return 0;

    if(!limited_read(c,1,region,parse_info))
	return 0;

    key->algorithm=c[0];

    switch(key->algorithm)
	{
    case OPS_PKA_DSA:
	if(!limited_read_mpi(&key->key.dsa.p,region,parse_info)
	   || !limited_read_mpi(&key->key.dsa.q,region,parse_info)
	   || !limited_read_mpi(&key->key.dsa.g,region,parse_info)
	   || !limited_read_mpi(&key->key.dsa.y,region,parse_info))
	    return 0;
	break;

    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:
	if(!limited_read_mpi(&key->key.rsa.n,region,parse_info)
	   || !limited_read_mpi(&key->key.rsa.e,region,parse_info))
	    return 0;
	break;

    case OPS_PKA_ELGAMAL:
    case OPS_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
	if(!limited_read_mpi(&key->key.elgamal.p,region,parse_info)
	   || !limited_read_mpi(&key->key.elgamal.g,region,parse_info)
	   || !limited_read_mpi(&key->key.elgamal.y,region,parse_info))
	    return 0;
	break;

    default:
	ERR1P(parse_info,"Unknown public key algorithm (%d)",key->algorithm);
	}

    return 1;
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
			    ops_parse_info_t *parse_info)
    {
    ops_parser_content_t content;

    if(!parse_public_key_data(&C.public_key,region,parse_info))
	return 0;

    // XXX: this test should be done for all packets, surely?
    if(region->length_read != region->length)
	ERR1P(parse_info,"Unconsumed data (%d)",
	      region->length-region->length_read);

    CBP(parse_info,tag,&content);

    return 1;
    }


/*! Free the memory used when parsing this signature sub-packet type */
void ops_ss_regexp_free(ops_ss_regexp_t *regexp)
    {
    string_free(&regexp->text);
    }

/*! Free the memory used when parsing this signature sub-packet type */
void ops_ss_policy_url_free(ops_ss_policy_url_t *policy_url)
    {
    string_free(&policy_url->text);
    }

/*! Free the memory used when parsing this signature sub-packet type */
void ops_ss_preferred_key_server_free(ops_ss_preferred_key_server_t *preferred_key_server)
    {
    string_free(&preferred_key_server->text);
    }

/*! Free the memory used when parsing this packet type */
void ops_user_attribute_free(ops_user_attribute_t *user_att)
    {
    data_free(&user_att->data);
    }

/** Parse one user attribute packet.
 *
 * User attribute packets contain one or more attribute subpackets.
 * For now, handle the whole packet as raw data.
 */

static int parse_user_attribute(ops_region_t *region, ops_parse_info_t *parse_info)
    {

    ops_parser_content_t content;

    /* xxx- treat as raw data for now. Could break down further
       into attribute sub-packets later - rachel */

    assert(region->length_read == 0);  /* We should not have read anything so far */

    if(!read_data(&C.user_attribute.data,region,parse_info))
	return 0;

    CBP(parse_info,OPS_PTAG_CT_USER_ATTRIBUTE,&content);

    return 1;
    }

/*! Free the memory used when parsing this packet type */
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
static int parse_user_id(ops_region_t *region,ops_parse_info_t *parse_info)
    {
    ops_parser_content_t content;

    assert(region->length_read == 0);  /* We should not have read anything so far */

    C.user_id.user_id=malloc(region->length+1);  /* XXX should we not like check malloc's return value? */

    if(region->length && !limited_read(C.user_id.user_id,region->length,region,
				       parse_info))
	return 0;

    C.user_id.user_id[region->length]='\0'; /* terminate the string */

    CBP(parse_info,OPS_PTAG_CT_USER_ID,&content);

    return 1;
    }

/**
 * \ingroup Memory
 *
 * Free the memory used when parsing a private/experimental PKA signature 
 *
 * \param unknown_sig
 */
void free_unknown_sig_pka(ops_unknown_signature_t *unknown_sig)
    {
    data_free(&unknown_sig->data);
    }

/**
 * \ingroup Memory
 *
 * Free the memory used when parsing a signature 
 *
 * \param sig
 */
void ops_signature_free(ops_signature_t *sig)
    {
    switch(sig->key_algorithm)
	{
    case OPS_PKA_RSA:
    case OPS_PKA_RSA_SIGN_ONLY:
	free_BN(&sig->signature.rsa.sig);
	break;

    case OPS_PKA_DSA:
	free_BN(&sig->signature.dsa.r);
	free_BN(&sig->signature.dsa.s);
	break;

    case OPS_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
	free_BN(&sig->signature.elgamal.r);
	free_BN(&sig->signature.elgamal.s);
	break;

    case OPS_PKA_PRIVATE00:
    case OPS_PKA_PRIVATE01:
    case OPS_PKA_PRIVATE02:
    case OPS_PKA_PRIVATE03:
    case OPS_PKA_PRIVATE04:
    case OPS_PKA_PRIVATE05:
    case OPS_PKA_PRIVATE06:
    case OPS_PKA_PRIVATE07:
    case OPS_PKA_PRIVATE08:
    case OPS_PKA_PRIVATE09:
    case OPS_PKA_PRIVATE10:
	free_unknown_sig_pka(&sig->signature.unknown);
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
static int parse_v3_signature(ops_region_t *region,
			      ops_parse_info_t *parse_info)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    C.signature.version=OPS_V3;

    /* hash info length */
    if(!limited_read(c,1,region,parse_info))
	return 0;
    if(c[0] != 5)
	ERRP(parse_info,"bad hash info length");

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.signature.type=c[0];
    /* XXX: check signature type */

    if(!limited_read_time(&C.signature.creation_time,region,parse_info))
	return 0;
    C.signature.creation_time_set=ops_true;

    if(!limited_read(C.signature.signer_id,OPS_KEY_ID_SIZE,region,parse_info))
	return 0;
    C.signature.signer_id_set=ops_true;

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.signature.key_algorithm=c[0];
    /* XXX: check algorithm */

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.signature.hash_algorithm=c[0];
    /* XXX: check algorithm */
    
    if(!limited_read(C.signature.hash2,2,region,parse_info))
	return 0;

    switch(C.signature.key_algorithm)
	{
    case OPS_PKA_RSA:
    case OPS_PKA_RSA_SIGN_ONLY:
	if(!limited_read_mpi(&C.signature.signature.rsa.sig,region,parse_info))
	    return 0;
	break;

    case OPS_PKA_DSA:
	if(!limited_read_mpi(&C.signature.signature.dsa.r,region,parse_info)
	   || !limited_read_mpi(&C.signature.signature.dsa.s,region,parse_info))
	    return 0;
	break;

    case OPS_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
	if(!limited_read_mpi(&C.signature.signature.elgamal.r,region,parse_info)
	   || !limited_read_mpi(&C.signature.signature.elgamal.s,region,parse_info))
	    return 0;
	break;

    default:
	ERR1P(parse_info,"Bad signature key algorithm (%d)",C.signature.key_algorithm);
	}

    if(region->length_read != region->length)
	ERR1P(parse_info,"Unconsumed data (%d)",region->length-region->length_read);

    CBP(parse_info,OPS_PTAG_CT_SIGNATURE,&content);

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
					 ops_parse_info_t *parse_info)
    {
    ops_region_t subregion;
    unsigned char c[1];
    ops_parser_content_t content;
    unsigned t8,t7;
    ops_boolean_t read=ops_true;
    unsigned char bool[1];

    ops_init_subregion(&subregion,region);
    if(!limited_read_new_length(&subregion.length,region,parse_info))
	return 0;

    if(subregion.length > region->length)
	ERRP(parse_info,"Subpacket too long");

    if(!limited_read(c,1,&subregion,parse_info))
	return 0;

    t8=(c[0]&0x7f)/8;
    t7=1 << (c[0]&7);

    content.critical=c[0] >> 7;
    content.tag=OPS_PTAG_SIGNATURE_SUBPACKET_BASE+(c[0]&0x7f);

    /* Application wants it delivered raw */
    if(parse_info->ss_raw[t8]&t7)
	{
	C.ss_raw.tag=content.tag;
	C.ss_raw.length=subregion.length-1;
	C.ss_raw.raw=malloc(C.ss_raw.length);
	if(!limited_read(C.ss_raw.raw,C.ss_raw.length,&subregion,parse_info))
	    return 0;
	CBP(parse_info,OPS_PTAG_RAW_SS,&content);
	return 1;
	}

    switch(content.tag)
	{
    case OPS_PTAG_SS_CREATION_TIME:
    case OPS_PTAG_SS_EXPIRATION_TIME:
    case OPS_PTAG_SS_KEY_EXPIRATION_TIME:
	if(!limited_read_time(&C.ss_time.time,&subregion,parse_info))
	    return 0;
	if(content.tag == OPS_PTAG_SS_CREATION_TIME)
	    {
	    sig->creation_time=C.ss_time.time;
	    sig->creation_time_set=ops_true;
	    }
	break;

    case OPS_PTAG_SS_TRUST:
	if(!limited_read(&C.ss_trust.level,1,&subregion,parse_info)
	   || !limited_read(&C.ss_trust.amount,1,&subregion,parse_info))
	    return 0;
	break;

    case OPS_PTAG_SS_REVOCABLE:
	if(!limited_read(bool,1,&subregion,parse_info))
	    return 0;
	C.ss_revocable.revocable=!!bool;
	break;

    case OPS_PTAG_SS_ISSUER_KEY_ID:
	if(!limited_read(C.ss_issuer_key_id.key_id,OPS_KEY_ID_SIZE,
			     &subregion,parse_info))
	    return 0;
	memcpy(sig->signer_id,C.ss_issuer_key_id.key_id,OPS_KEY_ID_SIZE);
	sig->signer_id_set=ops_true;
	break;

    case OPS_PTAG_SS_PREFERRED_SKA:
	if(!read_data(&C.ss_preferred_ska.data,&subregion,parse_info))
	    return 0;
	break;
			    	
    case OPS_PTAG_SS_PREFERRED_HASH:
	if(!read_data(&C.ss_preferred_hash.data,&subregion,parse_info))
	    return 0;
	break;
			    	
    case OPS_PTAG_SS_PREFERRED_COMPRESSION:
	if(!read_data(&C.ss_preferred_compression.data,&subregion,parse_info))
	    return 0;
	break;
			    	
    case OPS_PTAG_SS_PRIMARY_USER_ID:
	if(!limited_read (bool,1,&subregion,parse_info))
	    return 0;
	C.ss_primary_user_id.primary_user_id = !!bool;
	break;
 
    case OPS_PTAG_SS_KEY_FLAGS:
	if(!read_data(&C.ss_key_flags.data,&subregion,parse_info))
	    return 0;
	break;

    case OPS_PTAG_SS_KEY_SERVER_PREFS:
	if(!read_data(&C.ss_key_server_prefs.data,&subregion,parse_info))
	    return 0;
	break;

    case OPS_PTAG_SS_FEATURES:
	if(!read_data(&C.ss_features.data,&subregion,parse_info))
	    return 0;
	break;

    case OPS_PTAG_SS_SIGNERS_USER_ID:
	if(!read_unsigned_string(&C.ss_signers_user_id.user_id,&subregion,parse_info))
	    return 0;
	break;

    case OPS_PTAG_SS_NOTATION_DATA:
	if(!limited_read_data(&C.ss_notation_data.flags,4,&subregion,parse_info))
	    return 0;
	if(!limited_read_size_t_scalar(&C.ss_notation_data.name.len,2,
				       &subregion,parse_info))
	    return 0;
	if(!limited_read_size_t_scalar(&C.ss_notation_data.value.len,2,
				       &subregion,parse_info))
	    return 0;
	if(!limited_read_data(&C.ss_notation_data.name,
			      C.ss_notation_data.name.len,&subregion,parse_info))
	    return 0;
	if(!limited_read_data(&C.ss_notation_data.value,
			      C.ss_notation_data.value.len,&subregion,parse_info))
	    return 0;
	break;

    case OPS_PTAG_SS_POLICY_URL:
	if(!read_string(&C.ss_policy_url.text,&subregion,parse_info))
	    return 0;
	break;

    case OPS_PTAG_SS_REGEXP:
	if(!read_string(&C.ss_regexp.text,&subregion, parse_info))
	    return 0;
	break;

    case OPS_PTAG_SS_PREFERRED_KEY_SERVER:
	if(!read_string(&C.ss_preferred_key_server.text,&subregion,parse_info))
	    return 0;
	break;

    case OPS_PTAG_SS_USERDEFINED00:
    case OPS_PTAG_SS_USERDEFINED01:
    case OPS_PTAG_SS_USERDEFINED02:
    case OPS_PTAG_SS_USERDEFINED03:
    case OPS_PTAG_SS_USERDEFINED04:
    case OPS_PTAG_SS_USERDEFINED05:
    case OPS_PTAG_SS_USERDEFINED06:
    case OPS_PTAG_SS_USERDEFINED07:
    case OPS_PTAG_SS_USERDEFINED08:
    case OPS_PTAG_SS_USERDEFINED09:
    case OPS_PTAG_SS_USERDEFINED10:
	if(!read_data(&C.ss_userdefined.data,&subregion,parse_info))
	    return 0;
	break;

    case OPS_PTAG_SS_RESERVED:
	if(!read_data(&C.ss_unknown.data,&subregion,parse_info))
	    return 0;
	break;

    case OPS_PTAG_SS_REVOCATION_REASON:
	/* first byte is the machine-readable code */
	if(!limited_read(&C.ss_revocation_reason.code,1,&subregion,parse_info))
	    return 0;

	/* the rest is a human-readable UTF-8 string */
	if(!read_string(&C.ss_revocation_reason.text,&subregion,parse_info))
	    return 0;
	break;

    case OPS_PTAG_SS_REVOCATION_KEY:
	/* octet 0 = class. Bit 0x80 must be set */
	if(!limited_read (&C.ss_revocation_key.class,1,&subregion,parse_info))
	    return 0;
	if(!(C.ss_revocation_key.class&0x80))
	    {
	    printf("Warning: OPS_PTAG_SS_REVOCATION_KEY class: "
		   "Bit 0x80 should be set\n");
	    return 0;
	    }
 
	/* octet 1 = algid */
	if(!limited_read(&C.ss_revocation_key.algid,1,&subregion,parse_info))
	    return 0;
 
	/* octets 2-21 = fingerprint */
	if(!limited_read(&C.ss_revocation_key.fingerprint[0],20,&subregion,
			 parse_info))
	    return 0;
	break;
 
    default:
	if(parse_info->ss_parsed[t8]&t7)
	    ERR1P(parse_info,"Unknown signature subpacket type (%d)",
		  c[0]&0x7f);
	read=ops_false;
	break;
	}

    /* Application doesn't want it delivered parsed */
    if(!(parse_info->ss_parsed[t8]&t7))
	{
	if(content.critical)
	    ERR1P(parse_info,"Critical signature subpacket ignored (%d)",
		  c[0]&0x7f);
	if(!read && !limited_skip(subregion.length-1,&subregion,parse_info))
	    return 0;
	//	printf("skipped %d length %d\n",c[0]&0x7f,subregion.length);
	if(read)
	    ops_parser_content_free(&content);
	return 1;
	}

    if(read && subregion.length_read != subregion.length)
	ERR1P(parse_info,"Unconsumed data (%d)", subregion.length-subregion.length_read);
 
    CBP(parse_info,content.tag,&content);

    return 1;
    }

/*! Free the memory used when parsing this signature sub-packet type */
void ops_ss_preferred_ska_free(ops_ss_preferred_ska_t *ss_preferred_ska)
    {
    data_free(&ss_preferred_ska->data);
    }

/*! Free the memory used when parsing this signature sub-packet type */
void ops_ss_preferred_hash_free(ops_ss_preferred_hash_t *ss_preferred_hash)
    {
    data_free(&ss_preferred_hash->data);
    }

/*! Free the memory used when parsing this signature sub-packet type */
void ops_ss_preferred_compression_free(ops_ss_preferred_compression_t *ss_preferred_compression)
    {
    data_free(&ss_preferred_compression->data);
    }

/*! Free the memory used when parsing this signature sub-packet type */
void ops_ss_key_flags_free(ops_ss_key_flags_t *ss_key_flags)
    {
    data_free(&ss_key_flags->data);
    }

/*! Free the memory used when parsing this signature sub-packet type */
void ops_ss_features_free(ops_ss_features_t *ss_features)
    {
    data_free(&ss_features->data);
    }

/*! Free the memory used when parsing this signature sub-packet type */
void ops_ss_key_server_prefs_free(ops_ss_key_server_prefs_t *ss_key_server_prefs)
    {
    data_free(&ss_key_server_prefs->data);
    }

/** Parse several signature subpackets.
 *
 * Hashed and unhashed subpacket sets are preceded by an octet count that specifies the length of the complete set.
 * This function parses this length and then calls parse_one_signature_subpacket() for each subpacket until the
 * entire set is consumed.
 *
 * This function does not call the callback directly, parse_one_signature_subpacket() does for each subpacket.
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
				      ops_parse_info_t *parse_info)
    {
    ops_region_t subregion;
    ops_parser_content_t content;

    ops_init_subregion(&subregion,region);
    if(!limited_read_scalar(&subregion.length,2,region,parse_info))
	return 0;

    if(subregion.length > region->length)
	ERRP(parse_info,"Subpacket set too long");

    while(subregion.length_read < subregion.length)
	if(!parse_one_signature_subpacket(sig,&subregion,parse_info))
	    return 0;

    if(subregion.length_read != subregion.length)
	{
	if(!limited_skip(subregion.length-subregion.length_read,&subregion,
			 parse_info))
	    ERRP(parse_info,"Read failed while recovering from subpacket length mismatch");
	ERRP(parse_info,"Subpacket length mismatch");
	}

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
static int parse_v4_signature(ops_region_t *region,ops_parse_info_t *parse_info,
			      size_t v4_hashed_data_start)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    memset(&C.signature,'\0',sizeof C.signature);
    C.signature.version=OPS_V4;
    C.signature.v4_hashed_data_start=v4_hashed_data_start;

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.signature.type=c[0];
    /* XXX: check signature type */

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.signature.key_algorithm=c[0];
    /* XXX: check algorithm */

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.signature.hash_algorithm=c[0];
    /* XXX: check algorithm */

    CBP(parse_info,OPS_PTAG_CT_SIGNATURE_HEADER,&content);

    if(!parse_signature_subpackets(&C.signature,region,parse_info))
	return 0;
    C.signature.v4_hashed_data_length=parse_info->rinfo.alength
	-C.signature.v4_hashed_data_start;

    if(!parse_signature_subpackets(&C.signature,region,parse_info))
	return 0;
    
    if(!limited_read(C.signature.hash2,2,region,parse_info))
	return 0;

    switch(C.signature.key_algorithm)
	{
    case OPS_PKA_RSA:
	if(!limited_read_mpi(&C.signature.signature.rsa.sig,region,parse_info))
	    return 0;
	break;

    case OPS_PKA_DSA:
	if(!limited_read_mpi(&C.signature.signature.dsa.r,region,parse_info)) 
	    ERRP(parse_info,"Error reading DSA r field in signature");
	if (!limited_read_mpi(&C.signature.signature.dsa.s,region,parse_info))
	    ERRP(parse_info,"Error reading DSA s field in signature");
	break;

    case OPS_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
	if(!limited_read_mpi(&C.signature.signature.elgamal.r,region,parse_info)
	   || !limited_read_mpi(&C.signature.signature.elgamal.s,region,parse_info))
	    return 0;
	break;

    case OPS_PKA_PRIVATE00:
    case OPS_PKA_PRIVATE01:
    case OPS_PKA_PRIVATE02:
    case OPS_PKA_PRIVATE03:
    case OPS_PKA_PRIVATE04:
    case OPS_PKA_PRIVATE05:
    case OPS_PKA_PRIVATE06:
    case OPS_PKA_PRIVATE07:
    case OPS_PKA_PRIVATE08:
    case OPS_PKA_PRIVATE09:
    case OPS_PKA_PRIVATE10:
	if (!read_data(&C.signature.signature.unknown.data,region,parse_info))
	    return 0;
	break;

    default:
	ERR1P(parse_info,"Bad v4 signature key algorithm (%d)",
	      C.signature.key_algorithm);
	}

    if(region->length_read != region->length)
	ERR1P(parse_info,"Unconsumed data (%d)",
	      region->length-region->length_read);

    CBP(parse_info,OPS_PTAG_CT_SIGNATURE_FOOTER,&content);

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
static int parse_signature(ops_region_t *region,ops_parse_info_t *parse_info)
    {
    unsigned char c[1];
    ops_parser_content_t content;
    size_t v4_hashed_data_start;

    assert(region->length_read == 0);  /* We should not have read anything so far */

    memset(&content,'\0',sizeof content);

    v4_hashed_data_start=parse_info->rinfo.alength;
    if(!limited_read(c,1,region,parse_info))
	return 0;

    if(c[0] == 2 || c[0] == 3)
	return parse_v3_signature(region,parse_info);
    else if(c[0] == 4)
	return parse_v4_signature(region,parse_info,v4_hashed_data_start);
    ERR1P(parse_info,"Bad signature version (%d)",c[0]);
    }

static int parse_compressed(ops_region_t *region,ops_parse_info_t *parse_info)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    if(!limited_read(c,1,region,parse_info))
	return 0;

    C.compressed.type=c[0];

    CBP(parse_info,OPS_PTAG_CT_COMPRESSED,&content);

    /* The content of a compressed data packet is more OpenPGP packets
       once decompressed, so recursively handle them */

    return ops_decompress(region,parse_info);
    }

static int parse_one_pass(ops_region_t *region,ops_parse_info_t *parse_info)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    if(!limited_read(&C.one_pass_signature.version,1,region,parse_info))
	return 0;
    if(C.one_pass_signature.version != 3)
	ERR1P(parse_info,"Bad one-pass signature version (%d)",
	     C.one_pass_signature.version);

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.one_pass_signature.sig_type=c[0];

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.one_pass_signature.hash_algorithm=c[0];

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.one_pass_signature.key_algorithm=c[0];

    if(!limited_read(C.one_pass_signature.keyid,
			 sizeof C.one_pass_signature.keyid,region,parse_info))
	return 0;

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.one_pass_signature.nested=!!c[0];

    CBP(parse_info,OPS_PTAG_CT_ONE_PASS_SIGNATURE,&content);

    return 1;
    }

/*! Free the memory used when parsing this signature sub-packet type */
void ops_ss_userdefined_free(ops_ss_userdefined_t *ss_userdefined)
    {
    data_free(&ss_userdefined->data);
    }

/*! Free the memory used when parsing this signature sub-packet type */
void ops_ss_reserved_free(ops_ss_unknown_t *ss_unknown)
    {
    data_free(&ss_unknown->data);
    }

/*! Free the memory used when parsing this signature sub-packet type */
void ops_ss_notation_data_free(ops_ss_notation_data_t *ss_notation_data)
     {
     data_free(&ss_notation_data->name);
     data_free(&ss_notation_data->value);
     }

/*! Free the memory used when parsing this signature sub-packet type */
void ops_ss_revocation_reason_free(ops_ss_revocation_reason_t *ss_revocation_reason)
    {
    string_free(&ss_revocation_reason->text);
    }

/*! Free the memory used when parsing this packet type */
void ops_trust_free(ops_trust_t *trust)
    {
    data_free(&trust->data);
    }

static int
parse_trust (ops_region_t *region, ops_parse_info_t *parse_info)
    {
    ops_parser_content_t content;

    if(!read_data(&C.trust.data,region,parse_info))
	    return 0;

    CBP(parse_info,OPS_PTAG_CT_TRUST, &content);

    return 1;
    }

static int parse_literal_data(ops_region_t *region,ops_parse_info_t *parse_info)
    {
    ops_parser_content_t content;
    unsigned char c[1];

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.literal_data_header.format=c[0];

    if(!limited_read(c,1,region,parse_info))
	return 0;
    if(!limited_read((unsigned char *)C.literal_data_header.filename,c[0],
		     region,parse_info))
	return 0;
    C.literal_data_header.filename[c[0]]='\0';

    if(!limited_read_time(&C.literal_data_header.modification_time,region,parse_info))
	return 0;

    CBP(parse_info,OPS_PTAG_CT_LITERAL_DATA_HEADER,&content);

    while(region->length_read < region->length)
	{
	unsigned l=region->length-region->length_read;

	if(l > sizeof C.literal_data_body.data)
	    l=sizeof C.literal_data_body.data;

	if(!limited_read(C.literal_data_body.data,l,region,parse_info))
	    return 0;

	C.literal_data_body.length=l;

	CBP(parse_info,OPS_PTAG_CT_LITERAL_DATA_BODY,&content);
	}

    return 1;
    }

/**
 * \ingroup Memory
 *
 * ops_secret_key_free() frees the memory associated with "key". Note that
 * the key itself is not freed.
 * 
 * \param key
 */

void ops_secret_key_free(ops_secret_key_t *key)
    {
    switch(key->public_key.algorithm)
	{
    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:
	free_BN(&key->key.rsa.d);
	free_BN(&key->key.rsa.p);
	free_BN(&key->key.rsa.q);
	free_BN(&key->key.rsa.u);
	break;

    case OPS_PKA_DSA:
	free_BN(&key->key.dsa.x);
	break;

    default:
	fprintf(stderr,"Unknown algorithm: %d\n",key->public_key.algorithm);
	assert(0);
	}

    ops_public_key_free(&key->public_key);
    }

static int consume_packet(ops_region_t *region,ops_parse_info_t *parse_info,
			  ops_boolean_t warn)
    {
    ops_data_t remainder;
    ops_parser_content_t content;

    if(read_data(&remainder,region,parse_info))
	{
	/* now throw it away */
	data_free(&remainder);
	if(warn)
	    ERRCODEP(parse_info,OPS_E_P_PACKET_CONSUMED);
	}
    else if(warn)
	WARNP(parse_info,"Problem consuming remainder of error packet.");
    else
	return 0;

    return 1;
    }

static int parse_secret_key(ops_region_t *region,ops_parse_info_t *parse_info)
    {
    ops_parser_content_t content;
    unsigned char c[1];
    ops_decrypt_t decrypt;
    int ret=1;
    ops_region_t encregion;
    ops_region_t *saved_region=NULL;
    size_t checksum_length=2;
    ops_hash_t checkhash;
    int blocksize;
    ops_boolean_t crypted;

    memset(&content,'\0',sizeof content);
    if(!parse_public_key_data(&C.secret_key.public_key,region,parse_info))
	return 0;

    parse_info->reading_v3_secret=C.secret_key.public_key.version != OPS_V4;

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.secret_key.s2k_usage=c[0];

    if(C.secret_key.s2k_usage == OPS_S2KU_ENCRYPTED_AND_HASHED)
	checksum_length=20;

    if(C.secret_key.s2k_usage == OPS_S2KU_ENCRYPTED
       || C.secret_key.s2k_usage == OPS_S2KU_ENCRYPTED_AND_HASHED)
	{
	if(!limited_read(c,1,region,parse_info))
	    return 0;
	C.secret_key.algorithm=c[0];

	if(!limited_read(c,1,region,parse_info))
	    return 0;
	C.secret_key.s2k_specifier=c[0];

	assert(C.secret_key.s2k_specifier == OPS_S2KS_SIMPLE
	       || C.secret_key.s2k_specifier == OPS_S2KS_SALTED
	       || C.secret_key.s2k_specifier == OPS_S2KS_ITERATED_AND_SALTED);

	if(!limited_read(c,1,region,parse_info))
	    return 0;
	C.secret_key.hash_algorithm=c[0];

	if(C.secret_key.s2k_specifier != OPS_S2KS_SIMPLE
	   && !limited_read(C.secret_key.salt,8,region,parse_info))
	    return 0;

	if(C.secret_key.s2k_specifier == OPS_S2KS_ITERATED_AND_SALTED)
	    {
	    if(!limited_read(c,1,region,parse_info))
		return 0;
	    C.secret_key.octet_count=(16+(c[0]&15)) << ((c[0] >> 4)+6);
	    }
	}
    else if(C.secret_key.s2k_usage != OPS_S2KU_NONE)
	{
	// this is V3 style, looks just like a V4 simple hash
	C.secret_key.algorithm=C.secret_key.s2k_usage;
	C.secret_key.s2k_usage=OPS_S2KU_ENCRYPTED;
	C.secret_key.s2k_specifier=OPS_S2KS_SIMPLE;
	C.secret_key.hash_algorithm=OPS_HASH_MD5;
	}

    crypted=C.secret_key.s2k_usage == OPS_S2KU_ENCRYPTED
	|| C.secret_key.s2k_usage == OPS_S2KU_ENCRYPTED_AND_HASHED;

    if(crypted)
	{
	int n;
	ops_parser_content_t pc;
	char *passphrase;
	unsigned char key[OPS_MAX_KEY_SIZE+OPS_MAX_HASH_SIZE];
	ops_hash_t hashes[(OPS_MAX_KEY_SIZE+OPS_MIN_HASH_SIZE-1)/OPS_MIN_HASH_SIZE];
	int keysize;
	int hashsize;
	size_t l;

	blocksize=ops_block_size(C.secret_key.algorithm);
	assert(blocksize > 0 && blocksize <= OPS_MAX_BLOCK_SIZE);

	if(!limited_read(C.secret_key.iv,blocksize,region,parse_info))
	    return 0;

	memset(&pc,'\0',sizeof pc);
	passphrase=NULL;
	pc.content.secret_key_passphrase.passphrase=&passphrase;
	pc.content.secret_key_passphrase.secret_key=&C.secret_key;
	CBP(parse_info,OPS_PARSER_CMD_GET_SK_PASSPHRASE,&pc);
	if(!passphrase)
	    {
	    if(!consume_packet(region,parse_info,ops_false))
	       return 0;

	    CBP(parse_info,OPS_PTAG_CT_ENCRYPTED_SECRET_KEY,&content);

	    return 1;
	    }

	keysize=ops_key_size(C.secret_key.algorithm);
	assert(keysize > 0 && keysize <= OPS_MAX_KEY_SIZE);

	hashsize=ops_hash_size(C.secret_key.hash_algorithm);
	assert(hashsize > 0 && hashsize <= OPS_MAX_HASH_SIZE);

	for(n=0 ; n*hashsize < keysize ; ++n)
	    {
	    int i;

	    ops_hash_any(&hashes[n],C.secret_key.hash_algorithm);
	    hashes[n].init(&hashes[n]);
	    // preload hashes with zeroes...
	    for(i=0 ; i < n ; ++i)
		hashes[n].add(&hashes[n],"",1);
	    }

	l=strlen(passphrase);

	for(n=0 ; n*hashsize < keysize ; ++n)
	    {
	    unsigned i;

	    switch(C.secret_key.s2k_specifier)
		{
	    case OPS_S2KS_SALTED:
		hashes[n].add(&hashes[n],C.secret_key.salt,OPS_SALT_SIZE);
		// flow through...
	    case OPS_S2KS_SIMPLE:
		hashes[n].add(&hashes[n],passphrase,l);
		break;

	    case OPS_S2KS_ITERATED_AND_SALTED:
		for(i=0 ; i < C.secret_key.octet_count ; i+=l+OPS_SALT_SIZE)
		    {
		    int j=l+OPS_SALT_SIZE;

		    if(i+j > C.secret_key.octet_count && i != 0)
			j=C.secret_key.octet_count-i;

		    hashes[n].add(&hashes[n],C.secret_key.salt,
				  j > OPS_SALT_SIZE ? OPS_SALT_SIZE : j);
		    if(j > OPS_SALT_SIZE)
			hashes[n].add(&hashes[n],passphrase,j-OPS_SALT_SIZE);
		    }
			
		}
	    }

	for(n=0 ; n*hashsize < keysize ; ++n)
	    {
	    int r=hashes[n].finish(&hashes[n],key+n*hashsize);
	    assert(r == hashsize);
	    }

	free(passphrase);

	ops_decrypt_any(&decrypt,C.secret_key.algorithm);
	decrypt.set_iv(&decrypt,C.secret_key.iv);
	decrypt.set_key(&decrypt,key);

	ops_reader_push_decrypt(parse_info,&decrypt,region);

	/* Since all known encryption for PGP doesn't compress, we can
	   limit to the same length as the current region (for now).
	*/
	ops_init_subregion(&encregion,NULL);
	encregion.length=region->length-region->length_read;
	if(C.secret_key.public_key.version != OPS_V4)
	    encregion.length-=2;
	saved_region=region;
	region=&encregion;
	}

    if(C.secret_key.s2k_usage == OPS_S2KU_ENCRYPTED_AND_HASHED)
	{
	ops_hash_sha1(&checkhash);
	ops_reader_push_hash(parse_info,&checkhash);
	}
    else
	ops_reader_push_sum16(parse_info);

    switch(C.secret_key.public_key.algorithm)
	{
    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:
	if(!limited_read_mpi(&C.secret_key.key.rsa.d,region,parse_info)
	   || !limited_read_mpi(&C.secret_key.key.rsa.p,region,parse_info)
	   || !limited_read_mpi(&C.secret_key.key.rsa.q,region,parse_info)
	   || !limited_read_mpi(&C.secret_key.key.rsa.u,region,parse_info))
	    ret=0;
	break;

    case OPS_PKA_DSA:
	if(!limited_read_mpi(&C.secret_key.key.dsa.x,region,parse_info))
	    ret=0;
	break;

    default:
	fprintf(stderr,"Unexpected aglorithm: %d\n",
		C.secret_key.public_key.algorithm);
	ret=0;
	assert(0);
	}

    parse_info->reading_v3_secret=ops_false;

    if(C.secret_key.s2k_usage == OPS_S2KU_ENCRYPTED_AND_HASHED)
	{
	unsigned char hash[20];

	ops_reader_pop_hash(parse_info);
	checkhash.finish(&checkhash,hash);
	    
	if(crypted && C.secret_key.public_key.version != OPS_V4)
	    {
	    ops_reader_pop_decrypt(parse_info);
	    region=saved_region;
	    }

	if(ret)
	    {
	    if(!limited_read(C.secret_key.checkhash,20,region,parse_info))
		return 0;

	    if(memcmp(hash,C.secret_key.checkhash,20))
		ERRP(parse_info,"Hash mismatch in secret key");
	    }
	}
    else
	{
	unsigned short sum;

	sum=ops_reader_pop_sum16(parse_info);

	if(crypted && C.secret_key.public_key.version != OPS_V4)
	    {
	    ops_reader_pop_decrypt(parse_info);
	    region=saved_region;
	    }

	if(ret)
	    {
	    if(!limited_read_scalar(&C.secret_key.checksum,2,region,
				    parse_info))
		return 0;

	    if(sum != C.secret_key.checksum)
		ERRP(parse_info,"Checksum mismatch in secret key");
	    }
	}

    if(crypted && C.secret_key.public_key.version == OPS_V4)
	ops_reader_pop_decrypt(parse_info);

    assert(!ret || region->length_read == region->length);

    if(!ret)
	return 0;

    CBP(parse_info,OPS_PTAG_CT_SECRET_KEY,&content);

    return 1;
    }

static int parse_pk_session_key(ops_region_t *region,
				ops_parse_info_t *parse_info)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.pk_session_key.version=c[0];
    if(C.pk_session_key.version != OPS_PKSK_V3)
	ERR1P(parse_info,
	      "Bad public-key encrypted session key version (%d)",
	      C.pk_session_key.version);

    if(!limited_read(C.pk_session_key.key_id,
		     sizeof C.pk_session_key.key_id,region,parse_info))
	return 0;

    if(!limited_read(c,1,region,parse_info))
	return 0;
    C.pk_session_key.algorithm=c[0];
    switch(C.pk_session_key.algorithm)
	{
    case OPS_PKA_RSA:
	if(!limited_read_mpi(&C.pk_session_key.parameters.rsa.encrypted_m,
			     region,parse_info))
	    return 0;
	break;

    case OPS_PKA_ELGAMAL:
	if(!limited_read_mpi(&C.pk_session_key.parameters.elgamal.g_to_k,
			     region,parse_info)
	   || limited_read_mpi(&C.pk_session_key.parameters.elgamal.encrypted_m,
			     region,parse_info))
	    return 0;
	break;

    default:
	ERR1P(parse_info,
	      "Unknown public key algorithm in session key (%d)",
	      C.pk_session_key.algorithm);
	return 0;
	}

    CBP(parse_info,OPS_PTAG_CT_PK_SESSION_KEY,&content);

    return 1;
    }

static int parse_se_data(ops_region_t *region,ops_parse_info_t *parse_info)
    {
    ops_parser_content_t content;

    /* there's no info to go with this, so just announce it */
    CBP(parse_info,OPS_PTAG_CT_SE_DATA,&content);

    /* The content of an encrypted data packet is more OpenPGP packets
       once decompressed, so recursively handle them */
    return ops_decrypt_data(region,parse_info);
    }

/** Parse one packet.
 *
 * This function parses the packet tag.  It computes the value of the
 * content tag and then calls the appropriate function to handle the
 * content.
 *
 * \param *parse_info	How to parse
 * \param *pktlen	On return, will contain number of bytes in packet
 * \return 1 on success, 0 on error, -1 on EOF */
static int ops_parse_one_packet(ops_parse_info_t *parse_info,
				unsigned long *pktlen)
    {
    unsigned char ptag[1];
    ops_reader_ret_t ret;
    ops_parser_content_t content;
    int r;
    ops_region_t region;
    unsigned one=1;
    ops_boolean_t indeterminate=ops_false;

    C.ptag.position=parse_info->rinfo.position;

    ret=base_read(ptag,&one,0,parse_info);
    if(ret == OPS_R_EOF || ret == OPS_R_EARLY_EOF)
	return -1;

    *pktlen=0;

    assert(ret == OPS_R_OK);
    if(!(*ptag&OPS_PTAG_ALWAYS_SET))
	{
	C.error.error="Format error (ptag bit not set)";
	CBP(parse_info,OPS_PARSER_ERROR,&content);
	return 0;
	}
    C.ptag.new_format=!!(*ptag&OPS_PTAG_NEW_FORMAT);
    if(C.ptag.new_format)
	{
	C.ptag.content_tag=*ptag&OPS_PTAG_NF_CONTENT_TAG_MASK;
	C.ptag.length_type=0;
	if(!read_new_length(&C.ptag.length,parse_info))
	    return 0;

	}
    else
	{
	C.ptag.content_tag=(*ptag&OPS_PTAG_OF_CONTENT_TAG_MASK)
	    >> OPS_PTAG_OF_CONTENT_TAG_SHIFT;
	C.ptag.length_type=*ptag&OPS_PTAG_OF_LENGTH_TYPE_MASK;
	switch(C.ptag.length_type)
	    {
	case OPS_PTAG_OF_LT_ONE_BYTE:
	    ret=read_scalar(&C.ptag.length,1,parse_info);
	    break;

	case OPS_PTAG_OF_LT_TWO_BYTE:
	    ret=read_scalar(&C.ptag.length,2,parse_info);
	    break;

	case OPS_PTAG_OF_LT_FOUR_BYTE:
	    ret=read_scalar(&C.ptag.length,4,parse_info);
	    break;

	case OPS_PTAG_OF_LT_INDETERMINATE:
	    C.ptag.length=0;
	    indeterminate=ops_true;
	    ret=OPS_R_OK;
	    break;
	    }
	if(ret == OPS_R_EOF || ret == OPS_R_EARLY_EOF)
	    return -1;
	}

    CBP(parse_info,OPS_PARSER_PTAG,&content);

    ops_init_subregion(&region,NULL);
    region.length=C.ptag.length;
    region.indeterminate=indeterminate;
    switch(C.ptag.content_tag)
	{
    case OPS_PTAG_CT_SIGNATURE:
	r=parse_signature(&region,parse_info);
	break;

    case OPS_PTAG_CT_PUBLIC_KEY:
    case OPS_PTAG_CT_PUBLIC_SUBKEY:
	r=parse_public_key(C.ptag.content_tag,&region,parse_info);
	break;

    case OPS_PTAG_CT_TRUST:
	r=parse_trust(&region, parse_info);
	break;
      
    case OPS_PTAG_CT_USER_ID:
	r=parse_user_id(&region,parse_info);
	break;

    case OPS_PTAG_CT_COMPRESSED:
	r=parse_compressed(&region,parse_info);
	break;

    case OPS_PTAG_CT_ONE_PASS_SIGNATURE:
	r=parse_one_pass(&region,parse_info);
	break;

    case OPS_PTAG_CT_LITERAL_DATA:
	r=parse_literal_data(&region,parse_info);
	break;

    case OPS_PTAG_CT_USER_ATTRIBUTE:
	r=parse_user_attribute(&region,parse_info);
	break;

    case OPS_PTAG_CT_SECRET_KEY:
	r=parse_secret_key(&region,parse_info);
	break;

    case OPS_PTAG_CT_PK_SESSION_KEY:
	r=parse_pk_session_key(&region,parse_info);
	break;

    case OPS_PTAG_CT_SE_DATA:
	r=parse_se_data(&region,parse_info);
	break;

    default:
	format_error(&content,"Format error (unknown content tag %d)",
		     C.ptag.content_tag);
	ERRCODEP(parse_info,OPS_E_P_UNKNOWN_TAG);
	r=0;
	}

    /* Ensure that the entire packet has been consumed */

    if(region.length != region.length_read)
	consume_packet(&region,parse_info,ops_true);

    /* set pktlen */

    *pktlen=parse_info->rinfo.alength;

    /* do callback on entire packet, if desired */

    if(parse_info->rinfo.accumulate)
	{
	C.packet.length=parse_info->rinfo.alength;
	C.packet.raw=parse_info->rinfo.accumulated;
	parse_info->rinfo.accumulated=NULL;
	parse_info->rinfo.asize=0;
	CBP(parse_info,OPS_PARSER_PACKET_END,&content);
	}
    parse_info->rinfo.alength=0;
	
    return r ? 1 : 0;
    }

/**
 * \ingroup Parse
 * 
 * ops_parse() parses packets from an input stream until EOF or error.
 *
 * All the necessary information for parsing should have been set up by the
 * calling function in "*parse_info" beforehand.
 *
 * That information includes :
 *
 * - a "reader" function to be used to get the data to be parsed
 *
 * - a "callback" function to be called when this library has identified 
 * a parseable object within the data
 *
 * - whether the calling function wants the signature subpackets returned raw, parsed or not at all.
 *
 * \sa See Detailed Description for usage.
 *
 * \param *parse_info	How to parse
 * \return		1 on success in all packets, 0 on error in any packet
 * \todo Add some error checking to make sure *parse_info contains a sensible setup?
 */

int ops_parse(ops_parse_info_t *parse_info)
    {
    int r;
    unsigned long pktlen;
    do
	{
	r=ops_parse_one_packet(parse_info,&pktlen);
	//	offset+=pktlen;
	} while (r!=-1);

    return parse_info->errors ? 0 : 1;
    }

#if 0
/**
 *
 * \return 1 if success, 0 otherwise
 * XXX may not now be needed? RW
 */

int ops_parse_errs(ops_parse_info_t *parse_info, ops_ulong_list_t *errs)
    {
    unsigned err;
    int r;
    unsigned long pktlen;
    ops_reader_fd_arg_t *arg;
    int orig_acc;

    /* can only handle ops_reader_fd for now */

    if (parse_info->rinfo.reader != ops_reader_fd)
	{
	fprintf(stderr,"ops_parse_errs: can only handle ops_reader_fd\n");
	return 0;
	}

    arg=parse_info->rinfo.arg;

    /* store current state of accumulate flag */

    orig_acc=parse_info->rinfo.accumulate;

    /* set accumulate flag */

    parse_info->rinfo.accumulate=1;

    /* now parse each error in turn. */

    for(err=0; err < errs->used ; err++)
	{

	//	printf("\n***\n*** Error at offset %lu \n***\n",errs->ulongs[err]);

	/* move stream to offset of error */

	r=lseek(arg->fd,errs->ulongs[err],SEEK_SET);
	if (r==-1)
	    {
	    printf("error %d in first lseek to offset\n", errno);
	    return 0;
	    }

	/* parse packet */

	ops_parse_one_packet(parse_info,&pktlen);

	}

    /* restore accumulate flag original value */
    parse_info->rinfo.accumulate=orig_acc;

    return 1;
    }
#endif

/**
 * \ingroup Parse
 *
 * ops_parse_options() specifies whether one or more signature
 * subpacket types should be returned parsed or raw or ignored.
 *
 * \param	parse_info	Pointer to previously allocated structure
 * \param	tag	Packet tag. OPS_PTAG_SS_ALL for all SS tags; or one individual signature subpacket tag
 * \param	type	Parse type
 * \todo XXX: Make all packet types optional, not just subpackets */
void ops_parse_options(ops_parse_info_t *parse_info,
		       ops_content_tag_t tag,
		       ops_parse_type_t type)
    {
    int t8,t7;

    if(tag == OPS_PTAG_SS_ALL)
	{
	int n;

	for(n=0 ; n < 256 ; ++n)
	    ops_parse_options(parse_info,OPS_PTAG_SIGNATURE_SUBPACKET_BASE+n,
			      type);
	return;
	}

    assert(tag >= OPS_PTAG_SIGNATURE_SUBPACKET_BASE
	   && tag <= OPS_PTAG_SIGNATURE_SUBPACKET_BASE+NTAGS-1);
    t8=(tag-OPS_PTAG_SIGNATURE_SUBPACKET_BASE)/8;
    t7=1 << ((tag-OPS_PTAG_SIGNATURE_SUBPACKET_BASE)&7);
    switch(type)
	{
    case OPS_PARSE_RAW:
	parse_info->ss_raw[t8] |= t7;
	parse_info->ss_parsed[t8] &= ~t7;
	break;

    case OPS_PARSE_PARSED:
	parse_info->ss_raw[t8] &= ~t7;
	parse_info->ss_parsed[t8] |= t7;
	break;

    case OPS_PARSE_IGNORE:
	parse_info->ss_raw[t8] &= ~t7;
	parse_info->ss_parsed[t8] &= ~t7;
	break;
	}
    }

ops_parse_info_t *ops_parse_info_new(void)
    { return ops_mallocz(sizeof(ops_parse_info_t)); }

void ops_parse_info_delete(ops_parse_info_t *pinfo)
    { free(pinfo); }

ops_reader_info_t *ops_parse_get_rinfo(ops_parse_info_t *pinfo)
    { return &pinfo->rinfo; }

void ops_parse_cb_set(ops_parse_info_t *pinfo,ops_parse_cb_t *cb,void *arg)
    {
    pinfo->cbinfo.cb=cb;
    pinfo->cbinfo.arg=arg;
    }

void ops_parse_cb_push(ops_parse_info_t *pinfo,ops_parse_cb_t *cb,void *arg)
    {
    ops_parse_cb_info_t *cbinfo=malloc(sizeof *cbinfo);

    *cbinfo=pinfo->cbinfo;
    pinfo->cbinfo.next=cbinfo;
    ops_parse_cb_set(pinfo,cb,arg);
    }

void *ops_parse_cb_get_arg(ops_parse_cb_info_t *cbinfo)
    { return cbinfo->arg; }

ops_parse_cb_return_t ops_parse_cb(const ops_parser_content_t *content,
				   ops_parse_cb_info_t *cbinfo)
    { 
    if(cbinfo->cb)
	return cbinfo->cb(content,cbinfo); 
    else
	return OPS_FINISHED;
    }

ops_parse_cb_return_t ops_parse_stacked_cb(const ops_parser_content_t *content,
					   ops_parse_cb_info_t *cbinfo)
    { return ops_parse_cb(content,cbinfo->next); }

void ops_reader_set(ops_parse_info_t *pinfo,ops_reader_t *reader,void *arg)
    {
    pinfo->rinfo.reader=reader;
    pinfo->rinfo.arg=arg;
    }

void ops_reader_push(ops_parse_info_t *pinfo,ops_reader_t *reader,void *arg)
    {
    ops_reader_info_t *rinfo=malloc(sizeof *rinfo);

    *rinfo=pinfo->rinfo;
    pinfo->rinfo.next=rinfo;
    rinfo->pinfo=pinfo;
    ops_reader_set(pinfo,reader,arg);
    }

void ops_reader_pop(ops_parse_info_t *pinfo)
    { 
    ops_reader_info_t *next=pinfo->rinfo.next;

    pinfo->rinfo=*next;
    free(next);
    }

void *ops_reader_get_arg(ops_reader_info_t *rinfo)
    { return rinfo->arg; }

void *ops_reader_get_arg_from_pinfo(ops_parse_info_t *pinfo)
    { return pinfo->rinfo.arg; }

ops_error_t *ops_parse_info_get_errors(ops_parse_info_t *pinfo)
    { return pinfo->errors; }

ops_decrypt_t *ops_parse_get_decrypt(ops_parse_info_t *pinfo)
    { return pinfo->decrypt; }

/* vim:set textwidth=120: */
/* vim:set ts=8: */
