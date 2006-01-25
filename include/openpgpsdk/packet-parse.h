/** \file
 * Parser for OpenPGP packets - headers.
 */

#ifndef OPS_PACKET_PARSE_H
#define OPS_PACKET_PARSE_H

#include "types.h"
#include "packet.h"
#include "lists.h"

/** ops_region_t */
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
    OPS_R_ERROR		=4,	/*!< if there was an error reading */
    };

/** ops_parse_callback_return_t */
typedef enum
    {
    OPS_RELEASE_MEMORY,
    OPS_KEEP_MEMORY,
    OPS_FINISHED
    } ops_parse_cb_return_t;

typedef struct ops_parse_cb_info ops_parse_cb_info_t;

typedef ops_parse_cb_return_t
ops_parse_cb_t(const ops_parser_content_t *content,
	       ops_parse_cb_info_t *cbinfo);

typedef struct ops_parse_info ops_parse_info_t;
typedef struct ops_reader_info ops_reader_info_t;

typedef ops_reader_ret_t ops_reader_t(unsigned char *dest,
				      unsigned *plength,
				      ops_reader_flags_t flags,
				      ops_error_t **errors,
				      ops_reader_info_t *rinfo,
				      ops_parse_cb_info_t *cbinfo);
typedef void ops_reader_destroyer_t(ops_reader_info_t *rinfo);

ops_parse_info_t *ops_parse_info_new(void);
void ops_parse_info_delete(ops_parse_info_t *pinfo);
ops_error_t *ops_parse_info_get_errors(ops_parse_info_t *pinfo);
ops_decrypt_t *ops_parse_get_decrypt(ops_parse_info_t *pinfo);

void ops_parse_cb_set(ops_parse_info_t *pinfo,ops_parse_cb_t *cb,void *arg);
void ops_parse_cb_push(ops_parse_info_t *pinfo,ops_parse_cb_t *cb,void *arg);
void *ops_parse_cb_get_arg(ops_parse_cb_info_t *cbinfo);
void ops_reader_set(ops_parse_info_t *pinfo,ops_reader_t *reader,void *arg);
void ops_reader_push(ops_parse_info_t *pinfo,ops_reader_t *reader,void *arg);
void *ops_reader_get_arg_from_pinfo(ops_parse_info_t *pinfo);

void *ops_reader_get_arg(ops_reader_info_t *rinfo);

ops_parse_cb_return_t ops_parse_cb(const ops_parser_content_t *content,
				   ops_parse_cb_info_t *cbinfo);
ops_parse_cb_return_t ops_parse_stacked_cb(const ops_parser_content_t *content,
					   ops_parse_cb_info_t *cbinfo);
ops_reader_info_t *ops_parse_get_rinfo(ops_parse_info_t *pinfo);

int ops_parse(ops_parse_info_t *parse_info);
int ops_parse_and_save_errs(ops_parse_info_t *parse_info,ops_ulong_list_t *errs);
int ops_parse_errs(ops_parse_info_t *parse_info,ops_ulong_list_t *errs);

void ops_parse_and_validate(ops_parse_info_t *parse_info);

/** Used to specify whether subpackets should be returned raw, parsed or ignored.
 */
enum ops_parse_type_t
    {
    OPS_PARSE_RAW,	/*!< Callback Raw */
    OPS_PARSE_PARSED,	/*!< Callback Parsed */
    OPS_PARSE_IGNORE, 	/*!< Don't callback */
    };

void ops_parse_options(ops_parse_info_t *parse_info,ops_content_tag_t tag,
		       ops_parse_type_t type);

ops_boolean_t ops_limited_read(unsigned char *dest,unsigned length,
			       ops_region_t *region,ops_error_t **errors,
			       ops_reader_info_t *rinfo,
			       ops_parse_cb_info_t *cbinfo);
ops_boolean_t ops_stacked_limited_read(unsigned char *dest,unsigned length,
				       ops_region_t *region,
				       ops_error_t **errors,
				       ops_reader_info_t *rinfo,
				       ops_parse_cb_info_t *cbinfo);
ops_reader_ret_t ops_stacked_read(unsigned char *dest,unsigned *length,
			       ops_reader_flags_t flags,
			       ops_error_t **errors,
			       ops_reader_info_t *rinfo,
			       ops_parse_cb_info_t *cbinfo);

/* vim:set textwidth=120: */
/* vim:set ts=8: */

#endif
