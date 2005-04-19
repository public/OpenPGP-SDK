#include "util.h"
#include "packet-parse.h"
#include "crypto.h"
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

void hexdump(const unsigned char *src,size_t length)
    {
    while(length--)
	printf("%02X",*src++);
    }

void ops_init(void)
    {
    ops_crypto_init();
    }

void ops_finish(void)
    {
    ops_crypto_finish();
    }

ops_reader_ret_t ops_reader_fd(unsigned char *dest,unsigned *plength,
			       ops_reader_flags_t flags,void *arg_)
    {
    ops_reader_fd_arg_t *arg=arg_;
    int n=read(arg->fd,dest,*plength);

    if(n == 0)
	return OPS_R_EOF;

    if(n != *plength)
	{
	if(flags&OPS_RETURN_LENGTH)
	    {
	    *plength=n;
	    return OPS_R_EOF;
	    }
	else
	    return OPS_R_EARLY_EOF;
	}
#if 0
    printf("[read 0x%x: ",length);
    hexdump(dest,length);
    putchar(']');
#endif
    return OPS_R_OK;
    }

