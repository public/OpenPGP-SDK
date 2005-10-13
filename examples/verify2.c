#include "packet.h"
#include "packet-parse.h"
#include "util.h"
#include "accumulate.h"
#include "keyring.h"
#include "validate.h"
#include "armour.h"
#include "crypto.h"
#include "signature.h"
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

const char *pname;

static void usage()
    {
    fprintf(stderr,"%s [-a] <keyring> <file to verify>\n",pname);
    exit(1);
    }

static ops_keyring_t keyring;
static unsigned length;
static unsigned char *signed_data;
static ops_hash_t *signed_hash;

// FIXME: should this be a part of the library?
static ops_parse_callback_return_t
callback(const ops_parser_content_t *content_,void *arg_)
    {
    const ops_parser_content_union_t *content=&content_->content;
    const ops_key_data_t *signer;

    switch(content_->tag)
	{
    case OPS_PTAG_CT_SIGNED_CLEARTEXT_HEADER:
	free(signed_data);
	signed_data=NULL;
	length=0;
	break;

    case OPS_PTAG_CT_SIGNED_CLEARTEXT_BODY:
	signed_data=realloc(signed_data,
			    length+content->signed_cleartext_body.length);
	memcpy(signed_data+length,content->signed_cleartext_body.data,
	       content->signed_cleartext_body.length);
	length+=content->signed_cleartext_body.length;
	break;

    case OPS_PTAG_CT_SIGNED_CLEARTEXT_TRAILER:
	signed_hash=content->signed_cleartext_trailer.hash;
	return OPS_KEEP_MEMORY;

    case OPS_PTAG_CT_SIGNATURE:
	signer=ops_keyring_find_key_by_id(&keyring,
					  content->signature.signer_id);
	if(!signer)
	    {
	    fprintf(stderr,"SIGNER UNKNOWN!!!\n");
	    exit(2);
	    }

	if(ops_check_hash_signature(signed_hash,&content->signature,
				    ops_get_public_key_from_data(signer)))
	    {
	    puts("Good signature...\n");
	    fputs(signed_data,stdout);
	    free(signed_data);
	    length=0;
	    }
	else
	    {
	    fprintf(stderr,"BAD SIGNATURE!!!\n");
	    exit(1);
	    }
	break;

    case OPS_PARSER_ERROR:
	printf("parse error: %s\n",content->error.error);
	exit(1);
	break;

    case OPS_PTAG_CT_ARMOUR_HEADER:
	if(!strcmp(content->armour_header.type,"BEGIN PGP SIGNATURE"))
	    break;
	fprintf(stderr,"unexpected armour header: %s\n",
		content->armour_header.type);
	exit(3);
	break;

    case OPS_PTAG_CT_ARMOUR_TRAILER:
	if(!strcmp(content->armour_trailer.type,"END PGP SIGNATURE"))
	    break;
	fprintf(stderr,"unexpected armour trailer: %s\n",
		content->armour_header.type);
	exit(4);
	break;

    case OPS_PARSER_PTAG:
	// just ignore these
	break;

    default:
	fprintf(stderr,"Unexpected packet tag=%d (0x%x)\n",content_->tag,
		content_->tag);
	exit(1);
	}

    return OPS_RELEASE_MEMORY;
    }

int main(int argc,char **argv)
    {
    ops_parse_options_t opt;
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

    keyfile=argv[optind++];
    verify=argv[optind++];

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

    close(arg.fd);

    ops_dump_keyring(&keyring);

    ops_parse_options_init(&opt);

    arg.fd=open(verify,O_RDONLY);
    if(arg.fd < 0)
	{
	perror(verify);
	exit(2);
	}

    opt.reader_arg=&arg;
    opt.reader=ops_reader_fd;

    opt.cb=callback;

    if(armour)
	ops_push_dearmour(&opt);

    ops_parse(&opt);

    free(signed_data);
    ops_keyring_free(&keyring);
    ops_finish();

    return 0;
    }
