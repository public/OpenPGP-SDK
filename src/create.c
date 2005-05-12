#include "create.h"

static int base_write(const void *src,unsigned length,
		       ops_create_options_t *opt)
    {
    return opt->writer(src,length,0,opt->arg) == OPS_W_OK;
    }

int ops_write_scalar(unsigned n,unsigned length,ops_create_options_t *opt)
    {
    while(length-- > 0)
	{
	unsigned char c[1];

	c[0]=n >> (length*8);
	if(!base_write(c,1,opt))
	    return 0;
	}
    return 1;
    }

int ops_write_user_id(const char *user_id,ops_create_options_t *opt)
    {
    ops_user_id_t id;

    id.user_id=(char *)user_id;
    return ops_write_struct_user_id(&id,opt);
    }

int ops_write_struct_user_id(ops_user_id_t *id,ops_create_options_t *opt)
    {
    return ops_write_ptag(OPS_PTAG_CT_USER_ID,opt)
	&& ops_write_length(strlen(id->user_id),opt)
	&& ops_write(id->user_id,strlen(id->user_id),opt);
    }

int ops_write_ptag(ops_content_tag_t tag,ops_create_options_t *opt)
    {
    unsigned char c[1];

    c[0]=tag|OPS_PTAG_ALWAYS_SET|OPS_PTAG_NEW_FORMAT;

    return base_write(c,1,opt);
    }

int ops_write_length(unsigned length,ops_create_options_t *opt)
    {
    unsigned char c[5];

    if(length < 192)
	{
	c[0]=length;
	return base_write(c,1,opt);
	}
    else if(length < 8384)
	{
	c[0]=((length-192) >> 8)+192;
	c[1]=(length-192)%256;
	return base_write(c,2,opt);
	}
    c[0]=0xff;
    return ops_write_scalar(length,4,opt);
    }

int ops_write(const void *src,unsigned length,ops_create_options_t *opt)
    {
    return base_write(src,length,opt);
    }


