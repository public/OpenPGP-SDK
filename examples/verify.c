#include <openpgpsdk/packet.h>
#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/util.h>
#include <openpgpsdk/accumulate.h>
#include <openpgpsdk/keyring.h>
#include <openpgpsdk/validate.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <openpgpsdk/final.h>

int main(int argc,char **argv)
    {
    ops_parse_info_t *pinfo;
    ops_keyring_t keyring;
    const char *target;
    int fd;

    if(argc != 2)
	{
	fprintf(stderr,"%s <file to verify>\n",argv[0]);
	exit(1);
	}

    target=argv[1];

    ops_init();

    memset(&keyring,'\0',sizeof keyring);

    pinfo=ops_parse_info_new();

    if(!strcmp(target,"-"))
	fd=0;
    else
	{
	fd=open(target,O_RDONLY);
	if(fd < 0)
	    {
	    perror(target);
	    exit(2);
	    }
	}

    ops_reader_set_fd(pinfo,fd);

    ops_parse_and_accumulate(&keyring,pinfo);

    ops_dump_keyring(&keyring);

    ops_validate_all_signatures(&keyring);

    ops_keyring_free(&keyring);

    ops_finish();

    return 0;
    }
