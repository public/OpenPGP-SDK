typedef enum
    {
    OPS_PR_OK		=0,
    OPS_PR_EOF		=1,
    OPS_PR_EARLY_EOF	=2,
    } ops_packet_reader_ret;

typedef void ops_packet_parse_callback(ops_parser_content *content);
typedef ops_packet_reader_ret ops_packet_reader(unsigned char *dest,
						unsigned length);

void ops_parse_packet(ops_packet_reader *reader,ops_packet_parse_callback *cb);
