typedef enum
    {
    OPS_PR_OK		=0,
    OPS_PR_EOF		=1,
    OPS_PR_EARLY_EOF	=2,
    } ops_packet_reader_ret_t;

typedef void ops_packet_parse_callback_t(const ops_parser_content_t *content);
typedef ops_packet_reader_ret_t ops_packet_reader_t(unsigned char *dest,
						  unsigned length);

typedef struct
    {
    unsigned char ss_raw[256/8];
    unsigned char ss_parsed[256/8];
    } ops_parse_packet_options_t;

void ops_parse_packet(ops_packet_reader_t *reader,
		      ops_packet_parse_callback_t *cb,
		      ops_parse_packet_options_t *opt);

typedef enum
    {
    OPS_PARSE_RAW,
    OPS_PARSE_PARSED,
    OPS_PARSE_IGNORE
    } ops_parse_type_t;

#define ops_parse_packet_options_init(opt) memset(opt,'\0',sizeof *opt)

void ops_parse_packet_options(ops_parse_packet_options_t *opt,
			      ops_content_tag_t tag,
			      ops_parse_type_t type);

