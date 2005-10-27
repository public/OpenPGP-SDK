#include <openpgpsdk/create.h>
#include <openpgpsdk/util.h>
#include <stdio.h>

int main(int argc,char **argv)
    {
    ops_writer_fd_arg_t arg;
    ops_create_options_t opt;
    const unsigned char *id;
    const char *nstr;
    const char *estr;
    BIGNUM *n=NULL;
    BIGNUM *e=NULL;

    if(argc != 4)
	{
	fprintf(stderr,"%s <n> <e> <user id>\n",argv[0]);
	exit(1);
	}
    
    nstr=argv[1];
    estr=argv[2];
    id=(unsigned char *)argv[3];

    BN_hex2bn(&n,nstr);
    BN_hex2bn(&e,estr);

    arg.fd=1;
    opt.writer=ops_writer_fd;
    opt.arg=&arg;

    ops_write_rsa_public_key(time(NULL),n,e,&opt);
    ops_write_user_id(id,&opt);

    return 0;
    }
