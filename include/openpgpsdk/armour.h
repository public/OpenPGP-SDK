#include "packet-parse.h"
#include "signature.h"

void ops_reader_push_dearmour(ops_parse_info_t *parse_info,
			      ops_boolean_t without_gap,
			      ops_boolean_t no_gap,
			      ops_boolean_t trailing_whitespace);

void ops_reader_pop_dearmour(ops_parse_info_t *parse_info);
void ops_writer_push_clearsigned(ops_create_info_t *info,
				  ops_create_signature_t *sig);
void ops_writer_push_armoured_message(ops_create_info_t *info);
void ops_writer_switch_to_armoured_signature(ops_create_info_t *info);

typedef enum 
    {
    OPS_PGP_MESSAGE=1,
    OPS_PGP_PUBLIC_KEY_BLOCK,
    OPS_PGP_PRIVATE_KEY_BLOCK,
    OPS_PGP_MULTIPART_MESSAGE_PART_X_OF_Y,
    OPS_PGP_MULTIPART_MESSAGE_PART_X,
    OPS_PGP_SIGNATURE
    } ops_armor_type_t;

void ops_writer_push_armoured(ops_create_info_t *info, ops_armor_type_t type);

// EOF
