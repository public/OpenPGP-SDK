#include "packet.h"
#include "packet-parse.h"
#include "util.h"
#include "accumulate.h"
#include "keyring.h"
#include "validate.h"
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

const char *pname;

static void usage()
    {
    fprintf(stderr,"%s [-a] <keyring> <file to verify>\n",pname);
    exit(1);
    }

int main(int argc,char **argv)
    {
    ops_parse_options_t opt;
    ops_keyring_t keyring;
    ops_reader_fd_arg_t arg;
    const char *keyfile;
    const char *verify;
    int ch;
    ops_boolean_t armour=ops_false;

    pname=argv[0];

    while((ch=getopt(argc,argv,"a")) != -1)
	switch(ch)
	    {
	case 'a':
	    armour=ops_true;
	    break;

	default:
	    usage();
	    }

    keyfile=argv[1];
    verify=argv[2];

    ops_init();

    memset(&keyring,'\0',sizeof keyring);
    ops_parse_options_init(&opt);

    arg.fd=open(keyfile,O_RDONLY);
    if(arg.fd < 0)
	{
	perror(keyfile);
	exit(1);
	}

    opt.reader_arg=&arg;
    opt.reader=ops_reader_fd;

    ops_parse_and_accumulate(&keyring,&opt);

    ops_dump_keyring(&keyring);

    ops_keyring_free(&keyring);

    ops_finish();

    return 0;
    }
