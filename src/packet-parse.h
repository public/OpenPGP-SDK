typedef enum
    {
    OPS_PR_OK		=0,
    OPS_PR_EOF		=1,
    OPS_PR_EARLY_EOF	=2,
    } ops_packet_reader_ret_t;

typedef void ops_packet_parse_callback_t(const ops_parser_content_t *content);
typedef ops_packet_reader_ret_t ops_packet_reader_t(unsigned char *dest,
						  unsigned length);

void ops_parse_packet(ops_packet_reader_t *reader,
		      ops_packet_parse_callback_t *cb);
