/** \file packet-parse.h
 * Parser for OpenPGP packets - headers.
 *
 * $Id$
 */

/** Return values for #ops_packet_reader_t. */
typedef enum
    {
    OPS_PR_OK		=0,	/*!< success */
    OPS_PR_EOF		=1,	/*!< reached end of file, no data has been returned */
    OPS_PR_EARLY_EOF	=2,	/*!< could not read the requested amount of bytes */  /* XXX: How do we tell how many? */
    } ops_packet_reader_ret_t;

typedef enum
    {
    OPS_RELEASE_MEMORY,
    OPS_KEEP_MEMORY
    } ops_parse_callback_return_t;

typedef ops_parse_callback_return_t
ops_packet_parse_callback_t(const ops_parser_content_t *content,void *arg);
typedef ops_packet_reader_ret_t ops_packet_reader_t(unsigned char *dest,
						    unsigned length,
						    void *arg);

typedef struct
    {
    unsigned char ss_raw[256/8];
    unsigned char ss_parsed[256/8];
    ops_packet_parse_callback_t *cb;
    void *cb_arg;
    ops_packet_reader_t *_reader;
    unsigned accumulate:1;	/*!< accumulate packet data */
    unsigned char *accumulated;	/*!< the accumulated data */
    unsigned asize;	/*!< size of the buffer */
    unsigned alength;	/*!< used buffer */
    } ops_parse_options_t;

void ops_parse(ops_parse_options_t *opt);
void ops_parse_and_validate(ops_parse_options_t *opt);
void ops_parse_and_accumulate(ops_parse_options_t *opt);

typedef enum
    {
    OPS_PARSE_RAW,
    OPS_PARSE_PARSED,
    OPS_PARSE_IGNORE
    } ops_parse_type_t;

#define ops_parse_options_init(opt) memset(opt,'\0',sizeof *opt)

void ops_parse_options(ops_parse_options_t *opt,ops_content_tag_t tag,
		       ops_parse_type_t type);

void ops_content_free_inner(ops_parser_content_t *c);

/* vim:set textwidth=120: */
/* vim:set ts=8: */
