#include "packet.h"
#include "packet-parse.h"

typedef struct
    {
    ops_packet_parse_callback_t *cb;
    void *cb_arg;
    } validate_arg_t;

static void validate_cb(const ops_parser_content_t *content,void *arg_)
    {
    validate_arg_t *arg=arg_;

    arg->cb(content,arg->cb_arg);
    }


void ops_parse_and_validate(ops_packet_reader_t *reader,
			    ops_parse_options_t *opt)
    {
    validate_arg_t arg;

    arg.cb=opt->cb;
    arg.cb_arg=opt->cb_arg;
    opt->cb=validate_cb;
    opt->cb_arg=&arg;
    ops_parse(reader,opt);
    }
