#include "create.h"
#include "util.h"
#include <stdio.h>

int main(int argc,char **argv)
    {
    ops_writer_fd_arg_t arg;
    ops_create_options_t opt;

    const char *id;

    if(argc != 2)
	{
	fprintf(stderr,"%s <user id>\n",argv[0]);
	exit(1);
	}

    id=argv[1];

    arg.fd=1;
    opt.writer=ops_writer_fd;
    opt.arg=&arg;

    ops_write_user_id(id,&opt);

    return 0;
    }
