#include "common.h"
#include <openpgpsdk/util.h>
#include <memory.h>
#include <fcntl.h>
#include <assert.h>

static ops_parse_callback_return_t
callback(const ops_parser_content_t *content,void *arg_)
    {
    ops_secret_key_t **skey=arg_;

    if(content->tag == OPS_PTAG_CT_SECRET_KEY)
	{
	memcpy(skey,&content->content.secret_key,sizeof skey);
	return OPS_KEEP_MEMORY;
	}

    return OPS_RELEASE_MEMORY;
    }
    
ops_secret_key_t *get_secret_key(const char *keyfile)
    {
    ops_reader_fd_arg_t arg;
    ops_parse_info_t parse_info;
    ops_secret_key_t *skey;

    ops_parse_info_init(&parse_info);
    parse_info.cb=callback;

    arg.fd=open(keyfile,O_RDONLY);
    assert(arg.fd >= 0);
    parse_info.reader_arg=&arg;
    parse_info.reader=ops_reader_fd;

    skey=NULL;
    parse_info.cb_arg=&skey;

    ops_parse(&parse_info);

    return skey;
    }
