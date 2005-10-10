/** \file
 * Parser for OpenPGP packets - headers.
 */

#ifndef OPS_PACKET_PARSE_H
#define OPS_PACKET_PARSE_H

#include "types.h"
#include "packet.h"
#include "lists.h"

typedef struct ops_region
    {
    struct ops_region *parent;
    unsigned length;
    unsigned length_read;
    unsigned last_read; /*!< length of last read, only valid in deepest child */
    ops_boolean_t indeterminate:1;
    } ops_region_t;

void ops_init_subregion(ops_region_t *subregion,ops_region_t *region);

/** Return values for reader functions e.g. ops_packet_reader_t() */
enum ops_reader_ret_t
    {
    OPS_R_OK		=0,	/*!< success */
    OPS_R_EOF		=1,	/*!< reached end of file, no data has been returned */
    OPS_R_EARLY_EOF	=2,	/*!< could not read the requested
                                  number of bytes and either
                                  OPS_RETURN_LENGTH was not set and at
                                  least 1 byte was read, or there was
				  an abnormal end to the file (or
				  armoured block) */
    OPS_R_PARTIAL_READ	=3,	/*!< if OPS_RETURN_LENGTH is set and the buffer was not filled */
    };

typedef enum
    {
    OPS_RELEASE_MEMORY,
    OPS_KEEP_MEMORY
    } ops_parse_callback_return_t;

typedef ops_parse_callback_return_t
ops_packet_parse_callback_t(const ops_parser_content_t *content,void *arg);
typedef ops_reader_ret_t ops_packet_reader_t(unsigned char *dest,
					     unsigned *plength,
					     ops_reader_flags_t flags,
					     void *arg);

/** Structure to hold the options for parsing packets.
 */

typedef struct
    {
    unsigned char ss_raw[256/8]; /*!< one bit per signature-subpacket type; 
				    set to get raw data */
    unsigned char ss_parsed[256/8]; /*!< one bit per signature-subpacket type;
				       set to get parsed data */

    ops_packet_parse_callback_t *cb; /*!< the callback function to use when parsing */
    void *cb_arg; /*!< the args to pass to the callback function */

    ops_packet_reader_t *reader; /*!< the reader function to use to get the data to be parsed */
    void *reader_arg; /*!< the args to pass to the reader function */
    // XXX: what do we do about offsets into compressed packets?
    unsigned position; /*!< the offset from the beginning (with this reader) */

    unsigned accumulate:1;	/*!< set to accumulate packet data */
    unsigned char *accumulated;	/*!< the accumulated data */
    unsigned asize;	/*!< size of the buffer */
    unsigned alength;	/*!< used buffer */
    } ops_parse_options_t;

int ops_parse(ops_parse_options_t *opt);
int ops_parse_and_save_errs(ops_parse_options_t *opt,ops_ulong_list_t *errs);
int ops_parse_errs(ops_parse_options_t *opt,ops_ulong_list_t *errs);

void ops_parse_and_validate(ops_parse_options_t *opt);

/** Used to specify whether subpackets should be returned raw, parsed or ignored.
 */
enum ops_parse_type_t
    {
    OPS_PARSE_RAW,	/*!< Return Raw */
    OPS_PARSE_PARSED,	/*!< Return Parsed */
    OPS_PARSE_IGNORE 	/*!< Ignore - Return Nothing*/
    };

/** Initialise structure 
 */
#define ops_parse_options_init(opt) memset(opt,'\0',sizeof *opt)

void ops_parse_options(ops_parse_options_t *opt,ops_content_tag_t tag,
		       ops_parse_type_t type);

int ops_limited_read(unsigned char *dest,unsigned length,
		     ops_region_t *region,ops_parse_options_t *opt);

/* vim:set textwidth=120: */
/* vim:set ts=8: */

#endif
