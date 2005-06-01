/** \file
 */

#ifndef OPS_TYPES_H
#define OPS_TYPES_H

typedef struct 
    {
    int type;
    char *string;
    } map_t;

typedef unsigned ops_boolean_t;

typedef enum ops_content_tag_t ops_content_tag_t;

/* 
   keep both ops_content_tag_t and ops_packet_tag_t because we might
   want to introduce some bounds checking i.e. is this really a valid value
   for a packet tag? 
*/
typedef enum ops_content_tag_t ops_packet_tag_t;
typedef enum ops_content_tag_t ops_ss_type_t;
/* typedef enum ops_sig_type_t ops_sig_type_t; */

typedef unsigned char ops_ss_rr_code_t;

typedef enum ops_parse_type_t ops_parse_type_t;
typedef struct ops_parser_content_t ops_parser_content_t;

typedef enum
    {
    OPS_RETURN_LENGTH=1,
    } ops_reader_flags_t;
typedef enum ops_reader_ret_t ops_reader_ret_t;

typedef enum
    {
    OPS_WF_DUMMY,
    } ops_writer_flags_t;
typedef enum ops_writer_ret_t ops_writer_ret_t;


#endif
