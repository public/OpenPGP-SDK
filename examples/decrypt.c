#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/util.h>
#include <unistd.h>
#include <string.h>
#include <openpgpsdk/keyring.h>
#include <fcntl.h>
#include <openpgpsdk/accumulate.h>
#include <openpgpsdk/armour.h>

static char *pname;
static ops_keyring_t keyring;

static ops_parse_cb_return_t
cb_secret_key(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    const ops_parser_content_union_t *content=&content_->content;
    char buffer[1024];
    size_t n;

    OPS_USED(cbinfo);

    switch(content_->tag)
	{
    case OPS_PARSER_PTAG:
	break;

    case OPS_PTAG_CMD_GET_PASSPHRASE:
	printf("Passphrase: ");
	fgets(buffer,sizeof buffer,stdin);
	n=strlen(buffer);
	if(n && buffer[n-1] == '\n')
	    buffer[--n]='\0';
	*content->passphrase=malloc(n+1);
	strcpy(*content->passphrase,buffer);
	return OPS_KEEP_MEMORY;

    default:
	fprintf(stderr,"Unexpected packet tag=%d (0x%x)\n",content_->tag,
		content_->tag);
	exit(1);
	}

    return OPS_RELEASE_MEMORY;
    }

static ops_parse_cb_return_t
callback(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    //    const ops_parser_content_union_t *content=&content_->content;
    OPS_USED(cbinfo);

    switch(content_->tag)
	{
    default:
	fprintf(stderr,"Unexpected packet tag=%d (0x%x)\n",content_->tag,
		content_->tag);
	exit(1);
	}

    return OPS_RELEASE_MEMORY;
    }

static void usage()
    {
    fprintf(stderr,"%s [-a] <keyring> <file to decrypt>\n",pname);
    exit(1);
    }

int main(int argc,char **argv)
    {
    ops_parse_info_t *pinfo;
    int fd;
    const char *keyfile;
    const char *encfile;
    ops_boolean_t armour=ops_false;
    int ch;

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

    keyfile=argv[optind++];
    encfile=argv[optind++];

    ops_init();

    memset(&keyring,'\0',sizeof keyring);

    pinfo=ops_parse_info_new();

    fd=open(keyfile,O_RDONLY);
    if(fd < 0)
	{
	perror(keyfile);
	exit(1);
	}

    ops_reader_set_fd(pinfo,fd);

    ops_parse_cb_set(pinfo,cb_secret_key,NULL);

    ops_parse_and_accumulate(&keyring,pinfo);

    close(fd);

    pinfo=ops_parse_info_new();

    fd=open(encfile,O_RDONLY);
    if(fd < 0)
	{
	perror(encfile);
	exit(2);
	}

    ops_reader_set_fd(pinfo,fd);

    ops_parse_cb_set(pinfo,callback,NULL);

    if(armour)
	ops_reader_push_dearmour(pinfo,ops_false,ops_false,ops_false);

    ops_parse(pinfo);

    if(armour)
	ops_reader_pop_dearmour(pinfo);

    ops_keyring_free(&keyring);
    ops_finish();

    return 0;
    }


