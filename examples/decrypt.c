#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/util.h>
#include <openpgpsdk/keyring.h>
#include <openpgpsdk/accumulate.h>
#include <openpgpsdk/armour.h>

#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#include <openpgpsdk/final.h>

static char *pname;
static ops_keyring_t keyring;

static ops_parse_cb_return_t
callback(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    const ops_parser_content_union_t *content=&content_->content;
    static ops_boolean_t skipping;
    static const ops_key_data_t *decrypter;

    OPS_USED(cbinfo);

    if(content_->tag != OPS_PTAG_CT_UNARMOURED_TEXT && skipping)
	{
	puts("...end of skip");
	skipping=ops_false;
	}

    switch(content_->tag)
	{
    case OPS_PTAG_CT_UNARMOURED_TEXT:
	printf("OPS_PTAG_CT_UNARMOURED_TEXT\n");
	if(!skipping)
	    {
	    puts("Skipping...");
	    skipping=ops_true;
	    }
	fwrite(content->unarmoured_text.data,1,
	       content->unarmoured_text.length,stdout);
	break;

    case OPS_PTAG_CT_ARMOUR_HEADER:
    case OPS_PARSER_PTAG:
	printf ("OPS_PTAG_CT_ARMOUR_HEADER or OPS_PARSER_PTAG\n");
	break;

    case OPS_PTAG_CT_PK_SESSION_KEY:
	printf ("OPS_PTAG_CT_PK_SESSION_KEY\n");
	if(decrypter)
	    break;

	printf("looking for key\n");
	decrypter=ops_keyring_find_key_by_id(&keyring,
					     content->pk_session_key.key_id);
	if(!decrypter)
	    break;
	printf("found key\n");
	break;
	
    default:
	fprintf(stderr,"Unexpected packet tag=%d (0x%x)\n",content_->tag,
		content_->tag);
	assert(0);
	}

    return OPS_RELEASE_MEMORY;
    }

static void usage()
    {
    fprintf(stderr,"%s [-a] -k <keyring> -e <file to decrypt>\n",pname);
    exit(1);
    }

int main(int argc,char **argv)
    {
	    printf("argc: %d\n", argc);
    ops_parse_info_t *pinfo;
    int fd;
    const char *keyfile=(const char *)NULL;
    const char *encfile=(const char *)NULL;
    ops_boolean_t armour=ops_false;
    int ch;

    pname=argv[0];
	if (argc!=0)
	{
		usage();
		exit(1);
	}

    while((ch=getopt(argc,argv,"ak:e:")) != -1)
	switch(ch)
	    {
	case 'a':
	    armour=ops_true;
	    break;

	case 'k':
		keyfile=optarg;
		break;
		
	case 'e':
		encfile=optarg;
		break;
		
	default:
	    usage();
	    }

	argc-=optind;
	argv+=optind;
	
	if (argc!=0)
	{
		usage();
		exit(1);
	}
/*	
    keyfile=argv[optind++];
    encfile=argv[optind++];
*/
    ops_init();

    ops_keyring_read(&keyring,keyfile);

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


