#include "packet-parse.h"
#include "signature.h"

void ops_reader_push_dearmour(ops_parse_info_t *parse_info);
void ops_reader_pop_dearmour(ops_parse_info_t *parse_info);
void ops_writer_push_dash_escaped(ops_create_info_t *info,
				  ops_create_signature_t *sig);
void ops_writer_switch_to_signature(ops_create_info_t *info);

