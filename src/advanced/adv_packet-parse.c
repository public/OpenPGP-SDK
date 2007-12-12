/** \file
 * \brief Parser for OpenPGP packets
 */

#include <openssl/cast.h>

#include <openpgpsdk/packet.h>
#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/keyring.h>
#include <openpgpsdk/util.h>
#include <openpgpsdk/compress.h>
#include <openpgpsdk/errors.h>
#include <openpgpsdk/readerwriter.h>
#include "openpgpsdk/packet-show.h"

#include "parse_local.h"

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <errno.h>
#include <limits.h>

#include <openpgpsdk/final.h>

static int debug=0;

typedef struct
    {
    // boolean: false once we've done the preamble/MDC checks
    // and are reading from the plaintext
    int passed_checks; 
    unsigned char *plaintext;
    size_t plaintext_available;
    size_t plaintext_offset;
    ops_region_t *region;
    ops_crypt_t *decrypt;
    } decrypt_se_ip_arg_t;

/**
 * limited_read_data reads the specified amount of the subregion's data 
 * into a data_t structure
 *
 * \param data	Empty structure which will be filled with data
 * \param len	Number of octets to read
 * \param subregion
 * \param pinfo	How to parse
 *
 * \return 1 on success, 0 on failure
 */
static int limited_read_data(ops_data_t *data,unsigned int len,
			     ops_region_t *subregion,ops_parse_info_t *pinfo)
    {
    data->len = len;

    assert(subregion->length-subregion->length_read >= len);

    data->contents=malloc(data->len);
    if (!data->contents)
	return 0;

    if (!ops_limited_read(data->contents, data->len,subregion,&pinfo->errors,
			  &pinfo->rinfo,&pinfo->cbinfo))
	return 0;
    
    return 1;
    }

/**
 * read_data reads the remainder of the subregion's data 
 * into a data_t structure
 *
 * \param data
 * \param subregion
 * \param pinfo
 * 
 * \return 1 on success, 0 on failure
 */
static int read_data(ops_data_t *data,ops_region_t *subregion,
		     ops_parse_info_t *pinfo)
    {
    int len;

    len=subregion->length-subregion->length_read;

    if ( len >= 0 ) {
        return(limited_read_data(data,len,subregion,pinfo));
    }
    return 0;
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

static int read_string(char **str, ops_region_t *subregion, ops_parse_info_t *pinfo)
    {
    return (read_unsigned_string((unsigned char **)str, subregion, pinfo));
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
#ifdef XXX
/*! \todo descr ERR1 macro */
#define ERR1P(info,fmt,x)	do { format_error(&content,(fmt),(x)); CBP(info,OPS_PARSER_ERROR,&content); return ops_false; } while(0)
#define ERR2P(info,fmt,x,y)	do { format_error(&content,(fmt),(x),(y)); CBP(info,OPS_PARSER_ERROR,&content); return ops_false; } while(0)
#define ERR4P(info,fmt,x,y,z,a)	do { format_error(&content,(fmt),(x),(y),(z),(a)); CBP(info,OPS_PARSER_ERROR,&content); return ops_false; } while(0)
#endif

/* XXX: replace ops_ptag_t with something more appropriate for limiting
   reads */

#ifdef OLD
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
#endif

/**
 * low-level function to read data from reader function
 *
 * Use this function, rather than calling the reader directly.
 *
 * If the accumulate flag is set in *pinfo, the function
 * adds the read data to the accumulated data, and updates 
 * the accumulated length. This is useful if, for example, 
 * the application wants access to the raw data as well as the
 * parsed data.
 *
 * This function will also try to read the entire amount asked for, but not
 * if it is over INT_MAX. Obviously many callers will know that they
 * never ask for that much and so can avoid the extra complexity of
 * dealing with return codes and filled-in lengths.
 *
 * \param *dest
 * \param *plength
 * \param flags
 * \param *pinfo
 *
 * \return OPS_R_OK
 * \return OPS_R_PARTIAL_READ
 * \return OPS_R_EOF
 * \return OPS_R_EARLY_EOF
 * 
 * \sa #ops_reader_ret_t for details of return codes
 */

static int sub_base_read(void *dest,size_t length,ops_error_t **errors,
			 ops_reader_info_t *rinfo,ops_parse_cb_info_t *cbinfo)
    {
    size_t n;

    /* reading more than this would look like an error */
    if(length > INT_MAX)
	length=INT_MAX;

    for(n=0 ; n < length ; )
	{
	int r=rinfo->reader((char*)dest+n,length-n,errors,rinfo,cbinfo);

	assert(r <= (int)(length-n));

	// XXX: should we save the error and return what was read so far?
	if(r < 0)
	    return r;

	if(r == 0)
	    break;

	n+=r;
	}

    if(n == 0)
	return 0;

    if(rinfo->accumulate)
	{
	assert(rinfo->asize >= rinfo->alength);
	if(rinfo->alength+n > rinfo->asize)
	    {
	    rinfo->asize=rinfo->asize*2+n;
	    rinfo->accumulated=realloc(rinfo->accumulated,rinfo->asize);
	    }
	assert(rinfo->asize >= rinfo->alength+n);
	memcpy(rinfo->accumulated+rinfo->alength,dest,n);
	}
    // we track length anyway, because it is used for packet offsets
    rinfo->alength+=n;
    // and also the position
    rinfo->position+=n;

    return n;
    }

int ops_stacked_read(void *dest,size_t length,ops_error_t **errors,
		     ops_reader_info_t *rinfo,ops_parse_cb_info_t *cbinfo)
    { return sub_base_read(dest,length,errors,rinfo->next,cbinfo); }

/* This will do a full read so long as length < MAX_INT */
static int base_read(unsigned char *dest,size_t length,
		     ops_parse_info_t *pinfo)
    {
    return sub_base_read(dest,length,&pinfo->errors,&pinfo->rinfo,
			 &pinfo->cbinfo);
    }

/* Read a full size_t's worth. If the return is < than length, then
 * *last_read tells you why - < 0 for an error, == 0 for EOF */

static size_t full_read(unsigned char *dest,size_t length,int *last_read,
			ops_error_t **errors,ops_reader_info_t *rinfo,
			ops_parse_cb_info_t *cbinfo)
    {
    size_t t;
    int r=0; /* preset in case some loon calls with length == 0 */

    for(t=0 ; t < length ; )
	{
	r=sub_base_read(dest+t,length-t,errors,rinfo,cbinfo);

	if(r <= 0)
	    {
	    *last_read=r;
	    return t;
	    }

	t+=r;
	}

    *last_read=r;

    return t;
    }
	
	

/** Read a scalar value of selected length from reader.
 *
 * Read an unsigned scalar value from reader in Big Endian representation.
 *
 * This function does not know or care about packet boundaries. It
 * also assumes that an EOF is an error.
 *
 * \param *result	The scalar value is stored here
 * \param *reader	Our reader
 * \param length	How many bytes to read
 * \return		ops_true on success, ops_false on failure
 */
static ops_boolean_t _read_scalar(unsigned *result,unsigned length,
				    ops_parse_info_t *pinfo)
    {
    unsigned t=0;

    assert (length <= sizeof(*result));

    while(length--)
	{
	unsigned char c[1];
	int r;

	r=base_read(c,1,pinfo);
	if(r != 1)
	    return ops_false;
	t=(t << 8)+c[0];
	}

    *result=t;
    return ops_true;
    }

/** Read bytes from a region within the packet.
 *
 * Read length bytes into the buffer pointed to by *dest.  Make sure
 * we do not read over the packet boundary.  Updates the Packet Tag's
 * ops_ptag_t::length_read.
 *
 * If length would make us read over the packet boundary, or if
 * reading fails, we call the callback with an error.
 *
 * Note that if the region is indeterminate, this can return a short
 * read - check region->last_read for the length. EOF is indicated by
 * a success return and region->last_read == 0 in this case (for a
 * region of known length, EOF is an error).
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param *dest		The destination buffer
 * \param length	How many bytes to read
 * \param *region	Pointer to packet region
 * \param *pinfo	How to parse, including callback function
 * \return		ops_true on success, ops_false on error
 */
ops_boolean_t ops_limited_read(unsigned char *dest,size_t length,
			       ops_region_t *region,ops_error_t **errors,
			       ops_reader_info_t *rinfo,
			       ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_t content;
    size_t r;
    int lr;

    if(!region->indeterminate && region->length_read+length > region->length)
	{
	ERRCODE(cbinfo,OPS_E_P_NOT_ENOUGH_DATA);
	return 0;
	}

    r=full_read(dest,length,&lr,errors,rinfo,cbinfo);

    if(lr < 0)
	{
	ERRCODE(cbinfo,OPS_E_R_READ_FAILED);
	return ops_false;
	}

    if(!region->indeterminate && r != length)
	{
	ERRCODE(cbinfo,OPS_E_R_READ_FAILED);
	return ops_false;
	}

    region->last_read=r;
    do
	{
	region->length_read+=r;
	assert(!region->parent || region->length <= region->parent->length);
	}
    while((region=region->parent));

    return ops_true;
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

static ops_boolean_t exact_limited_read(unsigned char *dest,unsigned length,
					ops_region_t *region,
					ops_parse_info_t *pinfo)
    {
    ops_boolean_t ret;

    pinfo->exact_read=ops_true;
    ret=limited_read(dest,length,region,pinfo);
    pinfo->exact_read=ops_false;

    return ret;
    }

/** Skip over length bytes of this packet.
 *
 * Calls limited_read() to skip over some data.
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param length	How many bytes to skip
 * \param *region	Pointer to packet region
 * \param *pinfo	How to parse
 * \return		1 on success, 0 on error (calls the cb with OPS_PARSER_ERROR in limited_read()).
 */
static int limited_skip(unsigned length,ops_region_t *region,
			ops_parse_info_t *pinfo)
    {
    unsigned char buf[8192];

    while(length)
	{
	int n=length%8192;
	if(!limited_read(buf,n,region,pinfo))
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
 * \param *pinfo	How to parse
 * \param *cb		The callback
 * \return		1 on success, 0 on error (calls the cb with OPS_PARSER_ERROR in limited_read()).
 *
 * \see RFC2440bis-12 3.1
 */
static int limited_read_scalar(unsigned *dest,unsigned length,
			       ops_region_t *region,
			       ops_parse_info_t *pinfo)
    {
    unsigned char c[4];
    unsigned t;
    unsigned n;

    assert(length <= 4);
    assert(sizeof(*dest) >= 4);
    if(!limited_read(c,length,region,pinfo))
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
 * \param *pinfo	How to parse
 * \param *cb		The callback
 * \return		1 on success, 0 on error (calls the cb with OPS_PARSER_ERROR in limited_read()).
 *
 * \see RFC2440bis-12 3.1
 */
static int limited_read_size_t_scalar(size_t *dest,unsigned length,
				      ops_region_t *region,
				      ops_parse_info_t *pinfo)
    {
    unsigned tmp;

    assert(sizeof(*dest) >= 4);

    /* Note that because the scalar is at most 4 bytes, we don't care
       if size_t is bigger than usigned */
    if(!limited_read_scalar(&tmp,length,region,pinfo))
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
			     ops_parse_info_t *pinfo)
    {
    return limited_read_scalar((unsigned *)dest,4,region,pinfo);
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
			    ops_parse_info_t *pinfo)
    {
    unsigned length;
    unsigned nonzero;
    unsigned char buf[8192]; /* an MPI has a 2 byte length part.  Length
                                is given in bits, so the largest we should
                                ever need for the buffer is 8192 bytes. */
    ops_parser_content_t content;
    ops_boolean_t ret;

    pinfo->reading_mpi_length=ops_true;
    ret=limited_read_scalar(&length,2,region,pinfo);
    pinfo->reading_mpi_length=ops_false;
    if(!ret)
	return 0;

    nonzero=length&7; /* there should be this many zero bits in the MS byte */
    if(!nonzero)
	nonzero=8;
    length=(length+7)/8;

    assert(length <= 8192);
    if(!limited_read(buf,length,region,pinfo))
	return 0;

    if((buf[0] >> nonzero) != 0 || !(buf[0]&(1 << (nonzero-1))))
	{
	ERRCODEP(pinfo,OPS_E_P_MPI_FORMAT_ERROR);  /* XXX: Ben, one part of this constraint does not apply to encrypted MPIs the draft says. -- peter */
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
 * \param *pinfo	How to parse
 * \return		ops_true if OK, else ops_false
 *
 */

static ops_boolean_t read_new_length(unsigned *length,ops_parse_info_t *pinfo)
    {
    unsigned char c[1];

    if(base_read(c,1,pinfo) != 1)
	return ops_false;
    if(c[0] < 192)
	{
    // 1. One-octet packet
	*length=c[0];
	return ops_true;
	}

    else if (c[0]>=192 && c[0]<=223)
        {
        // 2. Two-octet packet
        unsigned t=(c[0]-192) << 8;
        
        if(base_read(c,1,pinfo) != 1)
            return ops_false;
        *length=t+c[0]+192;
        return ops_true;
        }

    else if (c[0]==255)
        {
        // 3. Five-Octet packet
        return _read_scalar(length,4,pinfo);
        }

    else if (c[0]>=224 && c[0]<255)
        {
        // 4. Partial Body Length
        OPS_ERROR(&pinfo->errors,OPS_E_UNIMPLEMENTED,
                    "New format Partial Body Length fields not yet implemented");
        return ops_false;
        }
    return ops_false;
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
				   ops_parse_info_t *pinfo)
    {
    unsigned char c[1];

    if(!limited_read(c,1,region,pinfo))
	return 0;
    if(c[0] < 192)
	{
	*length=c[0];
	return 1;
	}
    if(c[0] < 255)
	{
	unsigned t=(c[0]-192) << 8;

	if(!limited_read(c,1,region,pinfo))
	    return 0;
	*length=t+c[0]+192;
	return 1;
	}
    return limited_read_scalar(length,4,region,pinfo);
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
    // \todo check whether skp->passphrase should be static/dynamic
    if (skp->passphrase && *skp->passphrase)
        free(*(skp->passphrase));
    *(skp->passphrase)=NULL;
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
    case OPS_PTAG_CT_SE_DATA_HEADER:
    case OPS_PTAG_CT_SE_IP_DATA_HEADER:
    case OPS_PTAG_CT_SE_IP_DATA_BODY:
    case OPS_PTAG_CT_MDC:
    case OPS_PARSER_CMD_GET_SECRET_KEY:
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
    case OPS_PTAG_CT_ENCRYPTED_PK_SESSION_KEY:
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

 case 0:
     // nothing to free
     break;
     
    default:
	assert(0);
	}
    }

static int parse_public_key_data(ops_public_key_t *key,ops_region_t *region,
				 ops_parse_info_t *pinfo)
    {
    //    ops_parser_content_t content;
    unsigned char c[1];

    assert (region->length_read == 0);  /* We should not have read anything so far */

    if(!limited_read(c,1,region,pinfo))
	return 0;
    key->version=c[0];
    if(key->version < 2 || key->version > 4)
        {
	OPS_ERROR_1(&pinfo->errors,OPS_E_PROTO_BAD_PUBLIC_KEY_VRSN,
                    "Bad public key version (0x%02x)",key->version);
        return 0;
        }

    if(!limited_read_time(&key->creation_time,region,pinfo))
	return 0;

    key->days_valid=0;
    if((key->version == 2 || key->version == 3)
       && !limited_read_scalar(&key->days_valid,2,region,pinfo))
	return 0;

    if(!limited_read(c,1,region,pinfo))
	return 0;

    key->algorithm=c[0];

    switch(key->algorithm)
	{
    case OPS_PKA_DSA:
	if(!limited_read_mpi(&key->key.dsa.p,region,pinfo)
	   || !limited_read_mpi(&key->key.dsa.q,region,pinfo)
	   || !limited_read_mpi(&key->key.dsa.g,region,pinfo)
	   || !limited_read_mpi(&key->key.dsa.y,region,pinfo))
	    return 0;
	break;

    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:
	if(!limited_read_mpi(&key->key.rsa.n,region,pinfo)
	   || !limited_read_mpi(&key->key.rsa.e,region,pinfo))
	    return 0;
	break;

    case OPS_PKA_ELGAMAL:
    case OPS_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
	if(!limited_read_mpi(&key->key.elgamal.p,region,pinfo)
	   || !limited_read_mpi(&key->key.elgamal.g,region,pinfo)
	   || !limited_read_mpi(&key->key.elgamal.y,region,pinfo))
	    return 0;
	break;

    default:
	OPS_ERROR_1(&pinfo->errors,OPS_E_ALG_UNSUPPORTED_PUBLIC_KEY_ALG,"Unsupported Public Key algorithm (%s)",ops_show_pka(key->algorithm));
        return 0;
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
			    ops_parse_info_t *pinfo)
    {
    ops_parser_content_t content;

    if(!parse_public_key_data(&C.public_key,region,pinfo))
	return 0;

    // XXX: this test should be done for all packets, surely?
    if(region->length_read != region->length)
        {
        OPS_ERROR_1(&pinfo->errors,OPS_E_R_UNCONSUMED_DATA,
                    "Unconsumed data (%d)", region->length-region->length_read);
        return 0;
        }

    CBP(pinfo,tag,&content);

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

static int parse_user_attribute(ops_region_t *region, ops_parse_info_t *pinfo)
    {

    ops_parser_content_t content;

    /* xxx- treat as raw data for now. Could break down further
       into attribute sub-packets later - rachel */

    assert(region->length_read == 0);  /* We should not have read anything so far */

    if(!read_data(&C.user_attribute.data,region,pinfo))
	return 0;

    CBP(pinfo,OPS_PTAG_CT_USER_ATTRIBUTE,&content);

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
static int parse_user_id(ops_region_t *region,ops_parse_info_t *pinfo)
    {
    ops_parser_content_t content;

    assert(region->length_read == 0);  /* We should not have read anything so far */

    C.user_id.user_id=malloc(region->length+1);  /* XXX should we not like check malloc's return value? */

    if(region->length && !limited_read(C.user_id.user_id,region->length,region,
				       pinfo))
	return 0;

    C.user_id.user_id[region->length]='\0'; /* terminate the string */

    CBP(pinfo,OPS_PTAG_CT_USER_ID,&content);

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
			      ops_parse_info_t *pinfo)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    C.signature.version=OPS_V3;

    /* hash info length */
    if(!limited_read(c,1,region,pinfo))
	return 0;
    if(c[0] != 5)
	ERRP(pinfo,"bad hash info length");

    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.signature.type=c[0];
    /* XXX: check signature type */

    if(!limited_read_time(&C.signature.creation_time,region,pinfo))
	return 0;
    C.signature.creation_time_set=ops_true;

    if(!limited_read(C.signature.signer_id,OPS_KEY_ID_SIZE,region,pinfo))
	return 0;
    C.signature.signer_id_set=ops_true;

    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.signature.key_algorithm=c[0];
    /* XXX: check algorithm */

    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.signature.hash_algorithm=c[0];
    /* XXX: check algorithm */
    
    if(!limited_read(C.signature.hash2,2,region,pinfo))
	return 0;

    switch(C.signature.key_algorithm)
	{
    case OPS_PKA_RSA:
    case OPS_PKA_RSA_SIGN_ONLY:
	if(!limited_read_mpi(&C.signature.signature.rsa.sig,region,pinfo))
	    return 0;
	break;

    case OPS_PKA_DSA:
	if(!limited_read_mpi(&C.signature.signature.dsa.r,region,pinfo)
	   || !limited_read_mpi(&C.signature.signature.dsa.s,region,pinfo))
	    return 0;
	break;

    case OPS_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
	if(!limited_read_mpi(&C.signature.signature.elgamal.r,region,pinfo)
	   || !limited_read_mpi(&C.signature.signature.elgamal.s,region,pinfo))
	    return 0;
	break;

    default:
        OPS_ERROR_1(&pinfo->errors,OPS_E_ALG_UNSUPPORTED_SIGNATURE_ALG,
                    "Unsupported signature key algorithm (%s)",
                    ops_show_pka(C.signature.key_algorithm));
        return 0;
	}

    if(region->length_read != region->length)
        {
	OPS_ERROR_1(&pinfo->errors,OPS_E_R_UNCONSUMED_DATA,"Unconsumed data (%d)",region->length-region->length_read);
        return 0;
        }

    if(C.signature.signer_id_set)
	C.signature.hash=ops_parse_hash_find(pinfo,C.signature.signer_id);

    CBP(pinfo,OPS_PTAG_CT_SIGNATURE,&content);

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
					 ops_parse_info_t *pinfo)
    {
    ops_region_t subregion;
    unsigned char c[1];
    ops_parser_content_t content;
    unsigned t8,t7;
    ops_boolean_t read=ops_true;
    unsigned char bool[1];

    ops_init_subregion(&subregion,region);
    if(!limited_read_new_length(&subregion.length,region,pinfo))
	return 0;

    if(subregion.length > region->length)
	ERRP(pinfo,"Subpacket too long");

    if(!limited_read(c,1,&subregion,pinfo))
	return 0;

    t8=(c[0]&0x7f)/8;
    t7=1 << (c[0]&7);

    content.critical=c[0] >> 7;
    content.tag=OPS_PTAG_SIGNATURE_SUBPACKET_BASE+(c[0]&0x7f);

    /* Application wants it delivered raw */
    if(pinfo->ss_raw[t8]&t7)
	{
	C.ss_raw.tag=content.tag;
	C.ss_raw.length=subregion.length-1;
	C.ss_raw.raw=malloc(C.ss_raw.length);
	if(!limited_read(C.ss_raw.raw,C.ss_raw.length,&subregion,pinfo))
	    return 0;
	CBP(pinfo,OPS_PTAG_RAW_SS,&content);
    return 1;
	}

    switch(content.tag)
	{
    case OPS_PTAG_SS_CREATION_TIME:
    case OPS_PTAG_SS_EXPIRATION_TIME:
    case OPS_PTAG_SS_KEY_EXPIRATION_TIME:
	if(!limited_read_time(&C.ss_time.time,&subregion,pinfo))
	    return 0;
	if(content.tag == OPS_PTAG_SS_CREATION_TIME)
	    {
	    sig->creation_time=C.ss_time.time;
	    sig->creation_time_set=ops_true;
	    }
	break;

    case OPS_PTAG_SS_TRUST:
	if(!limited_read(&C.ss_trust.level,1,&subregion,pinfo)
	   || !limited_read(&C.ss_trust.amount,1,&subregion,pinfo))
	    return 0;
	break;

    case OPS_PTAG_SS_REVOCABLE:
	if(!limited_read(bool,1,&subregion,pinfo))
	    return 0;
	C.ss_revocable.revocable=!!bool;
	break;

    case OPS_PTAG_SS_ISSUER_KEY_ID:
	if(!limited_read(C.ss_issuer_key_id.key_id,OPS_KEY_ID_SIZE,
			     &subregion,pinfo))
	    return 0;
	memcpy(sig->signer_id,C.ss_issuer_key_id.key_id,OPS_KEY_ID_SIZE);
	sig->signer_id_set=ops_true;
	break;

    case OPS_PTAG_SS_PREFERRED_SKA:
	if(!read_data(&C.ss_preferred_ska.data,&subregion,pinfo))
	    return 0;
	break;
			    	
    case OPS_PTAG_SS_PREFERRED_HASH:
	if(!read_data(&C.ss_preferred_hash.data,&subregion,pinfo))
	    return 0;
	break;
			    	
    case OPS_PTAG_SS_PREFERRED_COMPRESSION:
	if(!read_data(&C.ss_preferred_compression.data,&subregion,pinfo))
	    return 0;
	break;
			    	
    case OPS_PTAG_SS_PRIMARY_USER_ID:
	if(!limited_read (bool,1,&subregion,pinfo))
	    return 0;
	C.ss_primary_user_id.primary_user_id = !!bool;
	break;
 
    case OPS_PTAG_SS_KEY_FLAGS:
	if(!read_data(&C.ss_key_flags.data,&subregion,pinfo))
	    return 0;
	break;

    case OPS_PTAG_SS_KEY_SERVER_PREFS:
	if(!read_data(&C.ss_key_server_prefs.data,&subregion,pinfo))
	    return 0;
	break;

    case OPS_PTAG_SS_FEATURES:
	if(!read_data(&C.ss_features.data,&subregion,pinfo))
	    return 0;
	break;

    case OPS_PTAG_SS_SIGNERS_USER_ID:
	if(!read_unsigned_string(&C.ss_signers_user_id.user_id,&subregion,pinfo))
	    return 0;
	break;

    case OPS_PTAG_SS_NOTATION_DATA:
	if(!limited_read_data(&C.ss_notation_data.flags,4,&subregion,pinfo))
	    return 0;
	if(!limited_read_size_t_scalar(&C.ss_notation_data.name.len,2,
				       &subregion,pinfo))
	    return 0;
	if(!limited_read_size_t_scalar(&C.ss_notation_data.value.len,2,
				       &subregion,pinfo))
	    return 0;
	if(!limited_read_data(&C.ss_notation_data.name,
			      C.ss_notation_data.name.len,&subregion,pinfo))
	    return 0;
	if(!limited_read_data(&C.ss_notation_data.value,
			      C.ss_notation_data.value.len,&subregion,pinfo))
	    return 0;
	break;

    case OPS_PTAG_SS_POLICY_URL:
	if(!read_string(&C.ss_policy_url.text,&subregion,pinfo))
	    return 0;
	break;

    case OPS_PTAG_SS_REGEXP:
	if(!read_string(&C.ss_regexp.text,&subregion, pinfo))
	    return 0;
	break;

    case OPS_PTAG_SS_PREFERRED_KEY_SERVER:
	if(!read_string(&C.ss_preferred_key_server.text,&subregion,pinfo))
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
	if(!read_data(&C.ss_userdefined.data,&subregion,pinfo))
	    return 0;
	break;

    case OPS_PTAG_SS_RESERVED:
	if(!read_data(&C.ss_unknown.data,&subregion,pinfo))
	    return 0;
	break;

    case OPS_PTAG_SS_REVOCATION_REASON:
	/* first byte is the machine-readable code */
	if(!limited_read(&C.ss_revocation_reason.code,1,&subregion,pinfo))
	    return 0;

	/* the rest is a human-readable UTF-8 string */
	if(!read_string(&C.ss_revocation_reason.text,&subregion,pinfo))
	    return 0;
	break;

    case OPS_PTAG_SS_REVOCATION_KEY:
	/* octet 0 = class. Bit 0x80 must be set */
	if(!limited_read (&C.ss_revocation_key.class,1,&subregion,pinfo))
	    return 0;
	if(!(C.ss_revocation_key.class&0x80))
	    {
	    printf("Warning: OPS_PTAG_SS_REVOCATION_KEY class: "
		   "Bit 0x80 should be set\n");
	    return 0;
	    }
 
	/* octet 1 = algid */
	if(!limited_read(&C.ss_revocation_key.algid,1,&subregion,pinfo))
	    return 0;
 
	/* octets 2-21 = fingerprint */
	if(!limited_read(&C.ss_revocation_key.fingerprint[0],20,&subregion,
			 pinfo))
	    return 0;
	break;
 
    default:
	if(pinfo->ss_parsed[t8]&t7)
	    OPS_ERROR_1(&pinfo->errors, OPS_E_PROTO_UNKNOWN_SS,
                        "Unknown signature subpacket type (%d)", c[0]&0x7f);
	read=ops_false;
	break;
	}

    /* Application doesn't want it delivered parsed */
    if(!(pinfo->ss_parsed[t8]&t7))
	{
	if(content.critical)
	    OPS_ERROR_1(&pinfo->errors,OPS_E_PROTO_CRITICAL_SS_IGNORED,
                        "Critical signature subpacket ignored (%d)",
                        c[0]&0x7f);
	if(!read && !limited_skip(subregion.length-1,&subregion,pinfo))
	    return 0;
	//	printf("skipped %d length %d\n",c[0]&0x7f,subregion.length);
	if(read)
	    ops_parser_content_free(&content);
	return 1;
	}

    if(read && subregion.length_read != subregion.length)
        {
	OPS_ERROR_1(&pinfo->errors,OPS_E_R_UNCONSUMED_DATA,
                    "Unconsumed data (%d)", 
                    subregion.length-subregion.length_read);
        return 0;
        }
 
    CBP(pinfo,content.tag,&content);

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
				      ops_parse_info_t *pinfo)
    {
    ops_region_t subregion;
    ops_parser_content_t content;

    ops_init_subregion(&subregion,region);
    if(!limited_read_scalar(&subregion.length,2,region,pinfo))
	return 0;

    if(subregion.length > region->length)
	ERRP(pinfo,"Subpacket set too long");

    while(subregion.length_read < subregion.length)
	if(!parse_one_signature_subpacket(sig,&subregion,pinfo))
	    return 0;

    if(subregion.length_read != subregion.length)
	{
	if(!limited_skip(subregion.length-subregion.length_read,&subregion,
			 pinfo))
	    ERRP(pinfo,"Read failed while recovering from subpacket length mismatch");
	ERRP(pinfo,"Subpacket length mismatch");
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
static int parse_v4_signature(ops_region_t *region,ops_parse_info_t *pinfo)
    {
    unsigned char c[1];
    ops_parser_content_t content;
    
    // clear signature
    memset(&C.signature,'\0',sizeof C.signature);

    /* We need to hash the packet data from version through the hashed subpacket data */

    C.signature.v4_hashed_data_start=pinfo->rinfo.alength-1;

    /* Set version,type,algorithms */

    C.signature.version=OPS_V4;

    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.signature.type=c[0];
    /* XXX: check signature type */

    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.signature.key_algorithm=c[0];
    /* XXX: check algorithm */

    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.signature.hash_algorithm=c[0];
    /* XXX: check algorithm */

    CBP(pinfo,OPS_PTAG_CT_SIGNATURE_HEADER,&content);

    if(!parse_signature_subpackets(&C.signature,region,pinfo))
	return 0;

    C.signature.v4_hashed_data_length=pinfo->rinfo.alength
        -C.signature.v4_hashed_data_start;

    // copy hashed subpackets
    if (C.signature.v4_hashed_data)
        free(C.signature.v4_hashed_data);
    C.signature.v4_hashed_data=ops_mallocz(C.signature.v4_hashed_data_length);

    if (!pinfo->rinfo.accumulate)
        {
        /* We must accumulate, else we can't check the signature */
        fprintf(stderr,"*** ERROR: must set accumulate to true\n");
        assert(0);
        }

    memcpy(C.signature.v4_hashed_data,
           pinfo->rinfo.accumulated+C.signature.v4_hashed_data_start,
           C.signature.v4_hashed_data_length);

    if(!parse_signature_subpackets(&C.signature,region,pinfo))
	return 0;
    
    if(!limited_read(C.signature.hash2,2,region,pinfo))
	return 0;

    switch(C.signature.key_algorithm)
	{
    case OPS_PKA_RSA:
	if(!limited_read_mpi(&C.signature.signature.rsa.sig,region,pinfo))
	    return 0;
	break;

    case OPS_PKA_DSA:
	if(!limited_read_mpi(&C.signature.signature.dsa.r,region,pinfo)) 
	    ERRP(pinfo,"Error reading DSA r field in signature");
	if (!limited_read_mpi(&C.signature.signature.dsa.s,region,pinfo))
	    ERRP(pinfo,"Error reading DSA s field in signature");
	break;

    case OPS_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
	if(!limited_read_mpi(&C.signature.signature.elgamal.r,region,pinfo)
	   || !limited_read_mpi(&C.signature.signature.elgamal.s,region,pinfo))
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
	if (!read_data(&C.signature.signature.unknown.data,region,pinfo))
	    return 0;
	break;

    default:
	OPS_ERROR_1(&pinfo->errors,OPS_E_ALG_UNSUPPORTED_SIGNATURE_ALG,
                    "Bad v4 signature key algorithm (%s)",
                    ops_show_pka(C.signature.key_algorithm));
        return 0;
	}

    if(region->length_read != region->length)
        {
	OPS_ERROR_1(&pinfo->errors,OPS_E_R_UNCONSUMED_DATA,
                    "Unconsumed data (%d)",
                    region->length-region->length_read);
        return 0;
        }

    CBP(pinfo,OPS_PTAG_CT_SIGNATURE_FOOTER,&content);

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
static int parse_signature(ops_region_t *region,ops_parse_info_t *pinfo)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    assert(region->length_read == 0);  /* We should not have read anything so far */

    memset(&content,'\0',sizeof content);

    if(!limited_read(c,1,region,pinfo))
	return 0;

    if(c[0] == 2 || c[0] == 3)
	return parse_v3_signature(region,pinfo);
    else if(c[0] == 4)
	return parse_v4_signature(region,pinfo);

    OPS_ERROR_1(&pinfo->errors,OPS_E_PROTO_BAD_SIGNATURE_VRSN,
                "Bad signature version (%d)",c[0]);
    return 0;
    }

static int parse_compressed(ops_region_t *region,ops_parse_info_t *pinfo)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    if(!limited_read(c,1,region,pinfo))
	return 0;

    C.compressed.type=c[0];

    CBP(pinfo,OPS_PTAG_CT_COMPRESSED,&content);

    /* The content of a compressed data packet is more OpenPGP packets
       once decompressed, so recursively handle them */

    return ops_decompress(region,pinfo,C.compressed.type);
    }

static int parse_one_pass(ops_region_t *region,ops_parse_info_t *pinfo)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    if(!limited_read(&C.one_pass_signature.version,1,region,pinfo))
	return 0;
    if(C.one_pass_signature.version != 3)
        {
	OPS_ERROR_1(&pinfo->errors,OPS_E_PROTO_BAD_ONE_PASS_SIG_VRSN,
                    "Bad one-pass signature version (%d)",
                    C.one_pass_signature.version);
        return 0;
        }

    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.one_pass_signature.sig_type=c[0];

    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.one_pass_signature.hash_algorithm=c[0];

    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.one_pass_signature.key_algorithm=c[0];

    if(!limited_read(C.one_pass_signature.keyid,
			 sizeof C.one_pass_signature.keyid,region,pinfo))
	return 0;

    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.one_pass_signature.nested=!!c[0];

    CBP(pinfo,OPS_PTAG_CT_ONE_PASS_SIGNATURE,&content);

    // XXX: we should, perhaps, let the app choose whether to hash or not
    ops_parse_hash_init(pinfo,C.one_pass_signature.hash_algorithm,
			C.one_pass_signature.keyid);

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
parse_trust (ops_region_t *region, ops_parse_info_t *pinfo)
    {
    ops_parser_content_t content;

    if(!read_data(&C.trust.data,region,pinfo))
	    return 0;

    CBP(pinfo,OPS_PTAG_CT_TRUST, &content);

    return 1;
    }

static int parse_literal_data(ops_region_t *region,ops_parse_info_t *pinfo)
    {
    ops_parser_content_t content;
    unsigned char c[1];

    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.literal_data_header.format=c[0];

    if(!limited_read(c,1,region,pinfo))
	return 0;
    if(!limited_read((unsigned char *)C.literal_data_header.filename,c[0],
		     region,pinfo))
	return 0;
    C.literal_data_header.filename[c[0]]='\0';

    if(!limited_read_time(&C.literal_data_header.modification_time,region,pinfo))
	return 0;

    CBP(pinfo,OPS_PTAG_CT_LITERAL_DATA_HEADER,&content);

    while(region->length_read < region->length)
	{
	unsigned l=region->length-region->length_read;

	if(l > sizeof C.literal_data_body.data)
	    l=sizeof C.literal_data_body.data;

	if(!limited_read(C.literal_data_body.data,l,region,pinfo))
	    return 0;

	C.literal_data_body.length=l;

	ops_parse_hash_data(pinfo,C.literal_data_body.data,l);

	CBP(pinfo,OPS_PTAG_CT_LITERAL_DATA_BODY,&content);
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

static int consume_packet(ops_region_t *region,ops_parse_info_t *pinfo,
			  ops_boolean_t warn)
    {
    ops_data_t remainder;
    ops_parser_content_t content;

    if(region->indeterminate)
	ERRP(pinfo,"Can't consume indeterminate packets");

    if(read_data(&remainder,region,pinfo))
	{
	/* now throw it away */
	data_free(&remainder);
	if(warn)
	    ERRCODEP(pinfo,OPS_E_P_PACKET_CONSUMED);
	}
    else if(warn)
	WARNP(pinfo,"Problem consuming remainder of error packet.");
    else
	{
	ERRCODEP(pinfo,OPS_E_P_PACKET_NOT_CONSUMED);
	return 0;
	}

    return 1;
    }

static int parse_secret_key(ops_region_t *region,ops_parse_info_t *pinfo)
    {
    ops_parser_content_t content;
    unsigned char c[1];
    ops_crypt_t decrypt;
    int ret=1;
    ops_region_t encregion;
    ops_region_t *saved_region=NULL;
    size_t checksum_length=2;
    ops_hash_t checkhash;
    int blocksize;
    ops_boolean_t crypted;

    memset(&content,'\0',sizeof content);
    if(!parse_public_key_data(&C.secret_key.public_key,region,pinfo))
	return 0;

    pinfo->reading_v3_secret=C.secret_key.public_key.version != OPS_V4;

    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.secret_key.s2k_usage=c[0];

    if(C.secret_key.s2k_usage == OPS_S2KU_ENCRYPTED_AND_HASHED)
	checksum_length=20;

    if(C.secret_key.s2k_usage == OPS_S2KU_ENCRYPTED
       || C.secret_key.s2k_usage == OPS_S2KU_ENCRYPTED_AND_HASHED)
	{
	if(!limited_read(c,1,region,pinfo))
	    return 0;
	C.secret_key.algorithm=c[0];

	if(!limited_read(c,1,region,pinfo))
	    return 0;
	C.secret_key.s2k_specifier=c[0];

	assert(C.secret_key.s2k_specifier == OPS_S2KS_SIMPLE
	       || C.secret_key.s2k_specifier == OPS_S2KS_SALTED
	       || C.secret_key.s2k_specifier == OPS_S2KS_ITERATED_AND_SALTED);

	if(!limited_read(c,1,region,pinfo))
	    return 0;
	C.secret_key.hash_algorithm=c[0];

	if(C.secret_key.s2k_specifier != OPS_S2KS_SIMPLE
	   && !limited_read(C.secret_key.salt,8,region,pinfo))
	    return 0;

	if(C.secret_key.s2k_specifier == OPS_S2KS_ITERATED_AND_SALTED)
	    {
	    if(!limited_read(c,1,region,pinfo))
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

	if(!limited_read(C.secret_key.iv,blocksize,region,pinfo))
	    return 0;

	memset(&pc,'\0',sizeof pc);
	passphrase=NULL;
	pc.content.secret_key_passphrase.passphrase=&passphrase;
	pc.content.secret_key_passphrase.secret_key=&C.secret_key;
	CBP(pinfo,OPS_PARSER_CMD_GET_SK_PASSPHRASE,&pc);
	if(!passphrase)
	    {
	    if(!consume_packet(region,pinfo,ops_false))
	       return 0;

	    CBP(pinfo,OPS_PTAG_CT_ENCRYPTED_SECRET_KEY,&content);

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
		hashes[n].add(&hashes[n],(unsigned char *)"",1);
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
		hashes[n].add(&hashes[n],(unsigned char*)passphrase,l);
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
			hashes[n].add(&hashes[n],(unsigned char *)passphrase,j-OPS_SALT_SIZE);
		    }
			
		}
	    }

	for(n=0 ; n*hashsize < keysize ; ++n)
	    {
	    int r=hashes[n].finish(&hashes[n],key+n*hashsize);
	    assert(r == hashsize);
	    }

	free(passphrase);

	ops_crypt_any(&decrypt,C.secret_key.algorithm);
	decrypt.set_iv(&decrypt,C.secret_key.iv);
	decrypt.set_key(&decrypt,key);

	ops_reader_push_decrypt(pinfo,&decrypt,region);

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
	ops_reader_push_hash(pinfo,&checkhash);
	}
    else
	ops_reader_push_sum16(pinfo);

    switch(C.secret_key.public_key.algorithm)
	{
    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:
	if(!limited_read_mpi(&C.secret_key.key.rsa.d,region,pinfo)
	   || !limited_read_mpi(&C.secret_key.key.rsa.p,region,pinfo)
	   || !limited_read_mpi(&C.secret_key.key.rsa.q,region,pinfo)
	   || !limited_read_mpi(&C.secret_key.key.rsa.u,region,pinfo))
	    ret=0;
	break;

    case OPS_PKA_DSA:
	if(!limited_read_mpi(&C.secret_key.key.dsa.x,region,pinfo))
	    ret=0;
	break;

    default:
	fprintf(stderr,"Unexpected algorithm: %d\n",
		C.secret_key.public_key.algorithm);
	ret=0;
	assert(0);
	}

    pinfo->reading_v3_secret=ops_false;

    if(C.secret_key.s2k_usage == OPS_S2KU_ENCRYPTED_AND_HASHED)
	{
	unsigned char hash[20];

	ops_reader_pop_hash(pinfo);
	checkhash.finish(&checkhash,hash);
	    
	if(crypted && C.secret_key.public_key.version != OPS_V4)
	    {
	    ops_reader_pop_decrypt(pinfo);
	    region=saved_region;
	    }

	if(ret)
	    {
	    if(!limited_read(C.secret_key.checkhash,20,region,pinfo))
		return 0;

	    if(memcmp(hash,C.secret_key.checkhash,20))
		ERRP(pinfo,"Hash mismatch in secret key");
	    }
	}
    else
	{
	unsigned short sum;

	sum=ops_reader_pop_sum16(pinfo);

	if(crypted && C.secret_key.public_key.version != OPS_V4)
	    {
	    ops_reader_pop_decrypt(pinfo);
	    region=saved_region;
	    }

	if(ret)
	    {
	    if(!limited_read_scalar(&C.secret_key.checksum,2,region,
				    pinfo))
		return 0;

	    if(sum != C.secret_key.checksum)
		ERRP(pinfo,"Checksum mismatch in secret key");
	    }
	}

    if(crypted && C.secret_key.public_key.version == OPS_V4)
	ops_reader_pop_decrypt(pinfo);

    assert(!ret || region->length_read == region->length);

    if(!ret)
	return 0;

    CBP(pinfo,OPS_PTAG_CT_SECRET_KEY,&content);

    return 1;
    }

static int parse_pk_session_key(ops_region_t *region,
                                ops_parse_info_t *pinfo)
    {
    unsigned char c[1];
    ops_parser_content_t content;
    ops_parser_content_t pc;

    int n;
    BIGNUM *enc_m;
    unsigned k;
    const ops_secret_key_t *secret;
    unsigned char cs[2];
    unsigned char* iv;

    // Can't rely on it being CAST5
    // \todo FIXME RW
    //    const size_t sz_unencoded_m_buf=CAST_KEY_LENGTH+1+2;
    const size_t sz_unencoded_m_buf=1024;
    unsigned char unencoded_m_buf[sz_unencoded_m_buf];
    
    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.pk_session_key.version=c[0];
    if(C.pk_session_key.version != OPS_PKSK_V3)
        {
	OPS_ERROR_1(&pinfo->errors, OPS_E_PROTO_BAD_PKSK_VRSN,
	      "Bad public-key encrypted session key version (%d)",
	      C.pk_session_key.version);
        return 0;
        }

    if(!limited_read(C.pk_session_key.key_id,
		     sizeof C.pk_session_key.key_id,region,pinfo))
	return 0;

    if (debug)
        {
        int i;
        int x=sizeof C.pk_session_key.key_id;
        printf("session key: public key id: x=%d\n",x);
        for (i=0; i<x; i++)
            printf("%2x ", C.pk_session_key.key_id[i]);
        printf("\n");
        }

    if(!limited_read(c,1,region,pinfo))
	return 0;
    C.pk_session_key.algorithm=c[0];
    switch(C.pk_session_key.algorithm)
	{
    case OPS_PKA_RSA:
	if(!limited_read_mpi(&C.pk_session_key.parameters.rsa.encrypted_m,
			     region,pinfo))
	    return 0;
	enc_m=C.pk_session_key.parameters.rsa.encrypted_m;
	break;

    case OPS_PKA_ELGAMAL:
	if(!limited_read_mpi(&C.pk_session_key.parameters.elgamal.g_to_k,
			     region,pinfo)
	   || !limited_read_mpi(&C.pk_session_key.parameters.elgamal.encrypted_m,
			     region,pinfo))
	    return 0;
	enc_m=C.pk_session_key.parameters.elgamal.encrypted_m;
	break;

    default:
	OPS_ERROR_1(&pinfo->errors, OPS_E_ALG_UNSUPPORTED_PUBLIC_KEY_ALG,
                    "Unknown public key algorithm in session key (%s)",
                    ops_show_pka(C.pk_session_key.algorithm));
	return 0;
	}

    memset(&pc,'\0',sizeof pc);
    secret=NULL;
    pc.content.get_secret_key.secret_key=&secret;
    pc.content.get_secret_key.pk_session_key=&C.pk_session_key;

    CBP(pinfo,OPS_PARSER_CMD_GET_SECRET_KEY,&pc);

    if(!secret)
	{
	CBP(pinfo,OPS_PTAG_CT_ENCRYPTED_PK_SESSION_KEY,&content);

	return 1;
	}

    //    n=ops_decrypt_mpi(buf,sizeof buf,enc_m,secret);
    n=ops_decrypt_and_unencode_mpi(unencoded_m_buf,sizeof unencoded_m_buf,enc_m,secret);

    if(n < 1)
        {
        ERRP(pinfo,"decrypted message too short");
        return 0;
        }

    // PKA
    C.pk_session_key.symmetric_algorithm=unencoded_m_buf[0];

    if (!ops_is_sa_supported(C.pk_session_key.symmetric_algorithm))
        {
        // ERR1P
        OPS_ERROR_1(&pinfo->errors,OPS_E_ALG_UNSUPPORTED_SYMMETRIC_ALG,
                    "Symmetric algorithm %s not supported", 
                    ops_show_symmetric_algorithm(C.pk_session_key.symmetric_algorithm));
        return 0;
        }

    k=ops_key_size(C.pk_session_key.symmetric_algorithm);

    if((unsigned)n != k+3)
        {
        OPS_ERROR_2(&pinfo->errors,OPS_E_PROTO_DECRYPTED_MSG_WRONG_LEN,
                    "decrypted message wrong length (got %d expected %d)",
                    n,k+3);
        return 0;
        }
    
    assert(k <= sizeof C.pk_session_key.key);

    memcpy(C.pk_session_key.key,unencoded_m_buf+1,k);

    if (debug)
        {
        printf("session key recovered (len=%d):\n",k);
        unsigned int j;
        for(j=0; j<k; j++)
            printf("%2x ", C.pk_session_key.key[j]);
        printf("\n");
        }

    C.pk_session_key.checksum=unencoded_m_buf[k+1]+(unencoded_m_buf[k+2] << 8);
    if (debug)
        {
        printf("session key checksum: %2x %2x\n", unencoded_m_buf[k+1], unencoded_m_buf[k+2]);
        }

    // Check checksum

    ops_calc_session_key_checksum(&C.pk_session_key, &cs[0]);
    if (unencoded_m_buf[k+1]!=cs[0] || unencoded_m_buf[k+2]!=cs[1])
        {
        OPS_ERROR_4(&pinfo->errors, OPS_E_PROTO_BAD_SK_CHECKSUM,
                    "Session key checksum wrong: expected %2x %2x, got %2x %2x",
              cs[0], cs[1], unencoded_m_buf[k+1], unencoded_m_buf[k+2]);
        return 0;
        }

    // all is well
    CBP(pinfo,OPS_PTAG_CT_PK_SESSION_KEY,&content);

    ops_crypt_any(&pinfo->decrypt,C.pk_session_key.symmetric_algorithm);
    iv=ops_mallocz(pinfo->decrypt.blocksize);
    pinfo->decrypt.set_iv(&pinfo->decrypt, iv);
    pinfo->decrypt.set_key(&pinfo->decrypt,C.pk_session_key.key);
    ops_encrypt_init(&pinfo->decrypt);
    return 1;
    }

static int se_ip_data_reader(void *dest_, size_t len, ops_error_t **errors,
                             ops_reader_info_t *rinfo,
                             ops_parse_cb_info_t *cbinfo)
    {

    /*
      Gets entire SE_IP data packet.
      Verifies leading preamble
      Verifies trailing MDC packet
      Then passes up plaintext as requested
    */

    unsigned int n=0;

    ops_region_t decrypted_region;

    decrypt_se_ip_arg_t *arg=ops_reader_get_arg(rinfo);

    if (!arg->passed_checks)
        {
        unsigned char*buf=NULL;

        ops_hash_t hash;
        unsigned char hashed[SHA_DIGEST_LENGTH];

        size_t b;
        size_t sz_preamble;
        size_t sz_mdc_hash;
        size_t sz_mdc;
        size_t sz_plaintext;

        unsigned char* preamble;
        unsigned char* plaintext;
        unsigned char* mdc;
        unsigned char* mdc_hash;

        ops_hash_any(&hash,OPS_HASH_SHA1);
        hash.init(&hash);

        ops_init_subregion(&decrypted_region,NULL);
        decrypted_region.length = arg->region->length - arg->region->length_read;
        buf=ops_mallocz(decrypted_region.length);

        // read entire SE IP packet
        
        if (!ops_stacked_limited_read(buf,decrypted_region.length, &decrypted_region,errors,rinfo,cbinfo))
            return -1;

        if (debug)
            {
            unsigned int i=0;
            fprintf(stderr,"\n\nentire SE IP packet (len=%d):\n",decrypted_region.length);
            for (i=0; i<decrypted_region.length; i++)
                {
                fprintf(stderr,"0x%02x ", buf[i]);
                if (!((i+1)%8))
                    fprintf(stderr,"\n");
                }
            fprintf(stderr,"\n");
            fprintf(stderr,"\n");
            }

        // verify leading preamble

        if (debug)
            {
            unsigned int i=0;
            fprintf(stderr,"\npreamble: ");
            for (i=0; i<arg->decrypt->blocksize+2;i++)
                fprintf(stderr," 0x%02x", buf[i]);
            fprintf(stderr,"\n");
            }

        b=arg->decrypt->blocksize;
        if(buf[b-2] != buf[b] || buf[b-1] != buf[b+1])
            {
            fprintf(stderr,"Bad symmetric decrypt (%02x%02x vs %02x%02x)\n",
                    buf[b-2],buf[b-1],buf[b],buf[b+1]);
            OPS_ERROR(errors, OPS_E_PROTO_BAD_SYMMETRIC_DECRYPT,"Bad symmetric decrypt when parsing SE IP packet");
            return -1;
            }

        // Verify trailing MDC hash

        sz_preamble=arg->decrypt->blocksize+2;
        sz_mdc_hash=OPS_SHA1_HASH_SIZE;
        sz_mdc=1+1+sz_mdc_hash;
        sz_plaintext=decrypted_region.length-sz_preamble-sz_mdc;

        preamble=buf;
        plaintext=buf+sz_preamble;
        mdc=plaintext+sz_plaintext;
        mdc_hash=mdc+2;
    
        if (debug)
            {
            unsigned int i=0;

            fprintf(stderr,"\nplaintext (len=%ld): ",sz_plaintext);
            for (i=0; i<sz_plaintext;i++)
                fprintf(stderr," 0x%02x", plaintext[i]);
            fprintf(stderr,"\n");

            fprintf(stderr,"\nmdc (len=%ld): ",sz_mdc);
            for (i=0; i<sz_mdc;i++)
                fprintf(stderr," 0x%02x", mdc[i]);
            fprintf(stderr,"\n");
            }

        ops_calc_mdc_hash(preamble,sz_preamble,plaintext,sz_plaintext,&hashed[0]);
        /*
        unsigned char c[0];

        hash.add(&hash, plaintext, sz_plaintext);
        c[0]=0xD3;
        hash.add(&hash,&c[0],1);   // MDC packet tag
        c[0]=0x14;
        hash.add(&hash,&c[0],1);   // MDC packet len
        
        hash.finish(&hash,&hashed[0]);
        */

        if (memcmp(mdc_hash,hashed,OPS_SHA1_HASH_SIZE))
            {
            fprintf(stderr,"Hash is bad\n");
            //            ERRP(pinfo,"Bad hash in MDC");
            return 0;
            }

        // all done with the checks
        // now can start reading from the plaintext
        assert(!arg->plaintext);
        arg->plaintext=ops_mallocz(sz_plaintext);
        memcpy(arg->plaintext, plaintext, sz_plaintext);
        arg->plaintext_available=sz_plaintext;

        arg->passed_checks=1;

        free(buf);
        }

    n=len;
    if (n > arg->plaintext_available)
        n=arg->plaintext_available;

    memcpy(dest_, arg->plaintext+arg->plaintext_offset, n);
    arg->plaintext_available-=n;
    arg->plaintext_offset+=n;
    len-=n;

    return n;
    }

static void se_ip_data_destroyer(ops_reader_info_t *rinfo)
    {
    decrypt_se_ip_arg_t* arg=ops_reader_get_arg(rinfo);
    free (arg->plaintext);
    free (arg);
    //    free(ops_reader_get_arg(rinfo));
    }

//void ops_reader_push_se_ip_data(ops_parse_info_t *pinfo __attribute__((__unused__)), ops_crypt_t *decrypt __attribute__((__unused__)),
//                                ops_region_t *region __attribute__((__unused__)))
void ops_reader_push_se_ip_data(ops_parse_info_t *pinfo, ops_crypt_t *decrypt,
                                ops_region_t *region)
    {
    decrypt_se_ip_arg_t *arg=ops_mallocz(sizeof *arg);
    arg->region=region;
    arg->decrypt=decrypt;

    ops_reader_push(pinfo, se_ip_data_reader, se_ip_data_destroyer,arg);
    }

void ops_reader_pop_se_ip_data(ops_parse_info_t* pinfo)
    {
    //    decrypt_se_ip_arg_t *arg=ops_reader_get_arg(ops_parse_get_rinfo(pinfo));
    //    free(arg);
    ops_reader_pop(pinfo);
    }

// XXX: make this static?
int ops_decrypt_se_data(ops_content_tag_t tag,ops_region_t *region,
		     ops_parse_info_t *pinfo)
    {
    int r=1;
    ops_crypt_t *decrypt=ops_parse_get_decrypt(pinfo);

    if(decrypt)
	{
	unsigned char buf[OPS_MAX_BLOCK_SIZE+2];
	size_t b=decrypt->blocksize;
        //	ops_parser_content_t content;
	ops_region_t encregion;


	ops_reader_push_decrypt(pinfo,decrypt,region);

	ops_init_subregion(&encregion,NULL);
	encregion.length=b+2;

	if(!exact_limited_read(buf,b+2,&encregion,pinfo))
	    return 0;

	if(buf[b-2] != buf[b] || buf[b-1] != buf[b+1])
	    {
	    ops_reader_pop_decrypt(pinfo);
	    OPS_ERROR_4(&pinfo->errors, OPS_E_PROTO_BAD_SYMMETRIC_DECRYPT,
                        "Bad symmetric decrypt (%02x%02x vs %02x%02x)",
                        buf[b-2],buf[b-1],buf[b],buf[b+1]);
            return 0;
	    }

	if(tag == OPS_PTAG_CT_SE_DATA_BODY)
	    {
	    decrypt->decrypt_resync(decrypt);
	    decrypt->block_encrypt(decrypt,decrypt->civ,decrypt->civ);
	    }


	r=ops_parse(pinfo);

	ops_reader_pop_decrypt(pinfo);
    }
    else
	{
	ops_parser_content_t content;

	while(region->length_read < region->length)
	    {
	    unsigned l=region->length-region->length_read;

	    if(l > sizeof C.se_data_body.data)
		l=sizeof C.se_data_body.data;

	    if(!limited_read(C.se_data_body.data,l,region,pinfo))
		return 0;

	    C.se_data_body.length=l;

	    CBP(pinfo,tag,&content);
	    }
	}

    return r;
    }

int ops_decrypt_se_ip_data(ops_content_tag_t tag,ops_region_t *region,
		     ops_parse_info_t *pinfo)
    {
    int r=1;
    ops_crypt_t *decrypt=ops_parse_get_decrypt(pinfo);

    if(decrypt)
        {
        ops_reader_push_decrypt(pinfo,decrypt,region);
        ops_reader_push_se_ip_data(pinfo,decrypt,region);

        r=ops_parse(pinfo);

        //        assert(0);
        ops_reader_pop_se_ip_data(pinfo);
        ops_reader_pop_decrypt(pinfo);
        }
    else
        {
        ops_parser_content_t content;
        
        while(region->length_read < region->length)
            {
            unsigned l=region->length-region->length_read;
            
            if(l > sizeof C.se_data_body.data)
                l=sizeof C.se_data_body.data;
            
            if(!limited_read(C.se_data_body.data,l,region,pinfo))
                return 0;
            
            C.se_data_body.length=l;
            
            CBP(pinfo,tag,&content);
            }
        }

    return r;
    }

static int parse_se_data(ops_region_t *region,ops_parse_info_t *pinfo)
    {
    ops_parser_content_t content;

    /* there's no info to go with this, so just announce it */
    CBP(pinfo,OPS_PTAG_CT_SE_DATA_HEADER,&content);

    /* The content of an encrypted data packet is more OpenPGP packets
       once decrypted, so recursively handle them */
    return ops_decrypt_se_data(OPS_PTAG_CT_SE_DATA_BODY,region,pinfo);
    }

static int parse_se_ip_data(ops_region_t *region,ops_parse_info_t *pinfo)
    {
    unsigned char c[1];
    ops_parser_content_t content;

    if(!limited_read(c,1,region,pinfo))
        return 0;
    C.se_ip_data_header.version=c[0];
    assert(C.se_ip_data_header.version == OPS_SE_IP_V1);

    /* The content of an encrypted data packet is more OpenPGP packets
       once decrypted, so recursively handle them */
    return ops_decrypt_se_ip_data(OPS_PTAG_CT_SE_IP_DATA_BODY,region,pinfo);
    }

static int parse_mdc(ops_region_t *region, ops_parse_info_t *pinfo)
	{
	ops_parser_content_t content;

	if (!limited_read((unsigned char *)&C.mdc,OPS_SHA1_HASH_SIZE,region,pinfo))
		return 0;

	CBP(pinfo,OPS_PTAG_CT_MDC,&content);

	return 1;
	}

/** Parse one packet.
 *
 * This function parses the packet tag.  It computes the value of the
 * content tag and then calls the appropriate function to handle the
 * content.
 *
 * \param *pinfo	How to parse
 * \param *pktlen	On return, will contain number of bytes in packet
 * \return 1 on success, 0 on error, -1 on EOF */
static int ops_parse_one_packet(ops_parse_info_t *pinfo,
				unsigned long *pktlen)
    {
    unsigned char ptag[1];
    ops_parser_content_t content;
    int r;
    ops_region_t region;
    ops_boolean_t indeterminate=ops_false;

    C.ptag.position=pinfo->rinfo.position;

    r=base_read(ptag,1,pinfo);

    // errors in the base read are effectively EOF.
    if(r <= 0)
	return -1;

    *pktlen=0;

    if(!(*ptag&OPS_PTAG_ALWAYS_SET))
	{
	C.error.error="Format error (ptag bit not set)";
	CBP(pinfo,OPS_PARSER_ERROR,&content);
	return 0;
	}
    C.ptag.new_format=!!(*ptag&OPS_PTAG_NEW_FORMAT);
    if(C.ptag.new_format)
	{
	C.ptag.content_tag=*ptag&OPS_PTAG_NF_CONTENT_TAG_MASK;
	C.ptag.length_type=0;
	if(!read_new_length(&C.ptag.length,pinfo))
	    return 0;

	}
    else
	{
	ops_boolean_t rb;

	C.ptag.content_tag=(*ptag&OPS_PTAG_OF_CONTENT_TAG_MASK)
	    >> OPS_PTAG_OF_CONTENT_TAG_SHIFT;
	C.ptag.length_type=*ptag&OPS_PTAG_OF_LENGTH_TYPE_MASK;
	switch(C.ptag.length_type)
	    {
	case OPS_PTAG_OF_LT_ONE_BYTE:
	    rb=_read_scalar(&C.ptag.length,1,pinfo);
	    break;

	case OPS_PTAG_OF_LT_TWO_BYTE:
	    rb=_read_scalar(&C.ptag.length,2,pinfo);
	    break;

	case OPS_PTAG_OF_LT_FOUR_BYTE:
	    rb=_read_scalar(&C.ptag.length,4,pinfo);
	    break;

	case OPS_PTAG_OF_LT_INDETERMINATE:
	    C.ptag.length=0;
	    indeterminate=ops_true;
	    rb=ops_true;
	    break;
	    }
	if(!rb)
	    return 0;
	}

    CBP(pinfo,OPS_PARSER_PTAG,&content);

    ops_init_subregion(&region,NULL);
    region.length=C.ptag.length;
    region.indeterminate=indeterminate;
    switch(C.ptag.content_tag)
	{
    case OPS_PTAG_CT_SIGNATURE:
	r=parse_signature(&region,pinfo);
	break;

    case OPS_PTAG_CT_PUBLIC_KEY:
    case OPS_PTAG_CT_PUBLIC_SUBKEY:
	r=parse_public_key(C.ptag.content_tag,&region,pinfo);
	break;

    case OPS_PTAG_CT_TRUST:
	r=parse_trust(&region, pinfo);
	break;
      
    case OPS_PTAG_CT_USER_ID:
	r=parse_user_id(&region,pinfo);
	break;

    case OPS_PTAG_CT_COMPRESSED:
	r=parse_compressed(&region,pinfo);
	break;

    case OPS_PTAG_CT_ONE_PASS_SIGNATURE:
	r=parse_one_pass(&region,pinfo);
	break;

    case OPS_PTAG_CT_LITERAL_DATA:
	r=parse_literal_data(&region,pinfo);
	break;

    case OPS_PTAG_CT_USER_ATTRIBUTE:
	r=parse_user_attribute(&region,pinfo);
	break;

    case OPS_PTAG_CT_SECRET_KEY:
	r=parse_secret_key(&region,pinfo);
	break;

    case OPS_PTAG_CT_SECRET_SUBKEY:
	r=parse_secret_key(&region,pinfo);
	break;

    case OPS_PTAG_CT_PK_SESSION_KEY:
	r=parse_pk_session_key(&region,pinfo);
	break;

    case OPS_PTAG_CT_SE_DATA:
	r=parse_se_data(&region,pinfo);
	break;

    case OPS_PTAG_CT_SE_IP_DATA:
	r=parse_se_ip_data(&region,pinfo);
	break;

    case OPS_PTAG_CT_MDC:
	 r=parse_mdc(&region, pinfo);
	 break;

    default:
	OPS_ERROR_1(&pinfo->errors,OPS_E_P_UNKNOWN_TAG,
                    "Unknown content tag 0x%x", C.ptag.content_tag);
	r=0;
	}

    /* Ensure that the entire packet has been consumed */

    if(region.length != region.length_read && !region.indeterminate)
	if(!consume_packet(&region,pinfo,ops_false))
	    r=-1;

    /* set pktlen */

    *pktlen=pinfo->rinfo.alength;

    /* do callback on entire packet, if desired and there was no error */

    if(r > 0 && pinfo->rinfo.accumulate)
	{
	C.packet.length=pinfo->rinfo.alength;
	C.packet.raw=pinfo->rinfo.accumulated;
	pinfo->rinfo.accumulated=NULL;
	pinfo->rinfo.asize=0;
	CBP(pinfo,OPS_PARSER_PACKET_END,&content);
	}
    pinfo->rinfo.alength=0;
	
    if(r < 0)
	return -1;

    return r ? 1 : 0;
    }

/**
 * \ingroup Parse
 * 
 * ops_parse() parses packets from an input stream until EOF or error.
 *
 * All the necessary information for parsing should have been set up by the
 * calling function in "*pinfo" beforehand.
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
 * \param *pinfo	How to parse
 * \return		1 on success in all packets, 0 on error in any packet
 * \todo Add some error checking to make sure *pinfo contains a sensible setup?
 */

int ops_parse(ops_parse_info_t *pinfo)
    {
    int r;
    unsigned long pktlen;

    do
	{
	r=ops_parse_one_packet(pinfo,&pktlen);
	} while (r != -1);

    return pinfo->errors ? 0 : 1;
    }

#if 0
/**
 *
 * \return 1 if success, 0 otherwise
 * XXX may not now be needed? RW
 */

int ops_parse_errs(ops_parse_info_t *pinfo, ops_ulong_list_t *errs)
    {
    unsigned err;
    int r;
    unsigned long pktlen;
    ops_reader_fd_arg_t *arg;
    int orig_acc;

    /* can only handle ops_reader_fd for now */

    if (pinfo->rinfo.reader != ops_reader_fd)
	{
	fprintf(stderr,"ops_parse_errs: can only handle ops_reader_fd\n");
	return 0;
	}

    arg=pinfo->rinfo.arg;

    /* store current state of accumulate flag */

    orig_acc=pinfo->rinfo.accumulate;

    /* set accumulate flag */

    pinfo->rinfo.accumulate=1;

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

	ops_parse_one_packet(pinfo,&pktlen);

	}

    /* restore accumulate flag original value */
    pinfo->rinfo.accumulate=orig_acc;

    return 1;
    }
#endif

/**
 * \ingroup Parse
 *
 * ops_parse_options() specifies whether one or more signature
 * subpacket types should be returned parsed or raw or ignored.
 *
 * \param	pinfo	Pointer to previously allocated structure
 * \param	tag	Packet tag. OPS_PTAG_SS_ALL for all SS tags; or one individual signature subpacket tag
 * \param	type	Parse type
 * \todo XXX: Make all packet types optional, not just subpackets */
void ops_parse_options(ops_parse_info_t *pinfo,
		       ops_content_tag_t tag,
		       ops_parse_type_t type)
    {
    int t8,t7;

    if(tag == OPS_PTAG_SS_ALL)
	{
	int n;

	for(n=0 ; n < 256 ; ++n)
	    ops_parse_options(pinfo,OPS_PTAG_SIGNATURE_SUBPACKET_BASE+n,
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
	pinfo->ss_raw[t8] |= t7;
	pinfo->ss_parsed[t8] &= ~t7;
	break;

    case OPS_PARSE_PARSED:
	pinfo->ss_raw[t8] &= ~t7;
	pinfo->ss_parsed[t8] |= t7;
	break;

    case OPS_PARSE_IGNORE:
	pinfo->ss_raw[t8] &= ~t7;
	pinfo->ss_parsed[t8] &= ~t7;
	break;
	}
    }

ops_parse_info_t *ops_parse_info_new(void)
    { return ops_mallocz(sizeof(ops_parse_info_t)); }

void ops_parse_info_delete(ops_parse_info_t *pinfo)
    {
    ops_parse_cb_info_t *cbinfo,*next;

    for(cbinfo=pinfo->cbinfo.next ; cbinfo ; cbinfo=next)
	{
	next=cbinfo->next;
	free(cbinfo);
	}
    if(pinfo->rinfo.destroyer)
	pinfo->rinfo.destroyer(&pinfo->rinfo);
    ops_free_errors(pinfo->errors);
    if(pinfo->rinfo.accumulated)
        free(pinfo->rinfo.accumulated);
    free(pinfo);
    }

ops_reader_info_t *ops_parse_get_rinfo(ops_parse_info_t *pinfo)
    { return &pinfo->rinfo; }

void ops_parse_cb_set(ops_parse_info_t *pinfo,ops_parse_cb_t *cb,void *arg)
    {
    pinfo->cbinfo.cb=cb;
    pinfo->cbinfo.arg=arg;
    pinfo->cbinfo.errors=&pinfo->errors;
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

void *ops_parse_cb_get_errors(ops_parse_cb_info_t *cbinfo)
    { return cbinfo->errors; }

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

/**
 * \brief
 * \param pinfo
 * \param reader
 * \param arg
 */
void ops_reader_set(ops_parse_info_t *pinfo,ops_reader_t *reader,ops_reader_destroyer_t *destroyer,void *arg)
    {
    pinfo->rinfo.reader=reader;
    pinfo->rinfo.destroyer=destroyer;
    pinfo->rinfo.arg=arg;
    }

/**
 * \brief 
 * \param pinfo
 * \param reader
 * \param arg
 */
void ops_reader_push(ops_parse_info_t *pinfo,ops_reader_t *reader,ops_reader_destroyer_t *destroyer,void *arg)
    {
    ops_reader_info_t *rinfo=malloc(sizeof *rinfo);

    *rinfo=pinfo->rinfo;
    memset(&pinfo->rinfo,'\0',sizeof pinfo->rinfo);
    pinfo->rinfo.next=rinfo;
    pinfo->rinfo.pinfo=pinfo;

    // should copy accumulate flags from other reader? RW
    pinfo->rinfo.accumulate=rinfo->accumulate;
    
    ops_reader_set(pinfo,reader,destroyer,arg);
    }

/**
 * \param pinfo
 */
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

ops_crypt_t *ops_parse_get_decrypt(ops_parse_info_t *pinfo)
    {
    if(pinfo->decrypt.algorithm)
	return &pinfo->decrypt;
    return NULL;
    }

// XXX: this could be improved by sharing all hashes that are the
// same, then duping them just before checking the signature.
void ops_parse_hash_init(ops_parse_info_t *pinfo,ops_hash_algorithm_t type,
			 const unsigned char *keyid)
    {
    ops_parse_hash_info_t *hash;

    pinfo->hashes=realloc(pinfo->hashes,
			  (pinfo->nhashes+1)*sizeof *pinfo->hashes);
    hash=&pinfo->hashes[pinfo->nhashes++];

    ops_hash_any(&hash->hash,type);
    hash->hash.init(&hash->hash);
    memcpy(hash->keyid,keyid,sizeof hash->keyid);
    }

void ops_parse_hash_data(ops_parse_info_t *pinfo,const void *data,
			 size_t length)
    {
    size_t n;

    for(n=0 ; n < pinfo->nhashes ; ++n)
	pinfo->hashes[n].hash.add(&pinfo->hashes[n].hash,data,length);
    }

ops_hash_t *ops_parse_hash_find(ops_parse_info_t *pinfo,
				const unsigned char keyid[OPS_KEY_ID_SIZE])
    {
    size_t n;

    for(n=0 ; n < pinfo->nhashes ; ++n)
	if(!memcmp(pinfo->hashes[n].keyid,keyid,OPS_KEY_ID_SIZE))
	    return &pinfo->hashes[n].hash;
    return NULL;
    }

/* vim:set textwidth=120: */
/* vim:set ts=8: */
