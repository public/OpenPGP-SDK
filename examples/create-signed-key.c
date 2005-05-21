#include "create.h"
#include "util.h"
#include "signature.h"
#include "packet-parse.h"
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>

/*
 * Slightly strange beast that might get replaced later - it needs
 * some other OpenPGP package to generate a key for it to use - this
 * is because we don't have a way to generate our own (yet).
 */

static ops_secret_key_t skey;
static ops_boolean_t skey_found;

static ops_parse_callback_return_t
callback(const ops_parser_content_t *content,void *arg_)
    {
    if(content->tag == OPS_PTAG_CT_SECRET_KEY)
	{
	memcpy(&skey,&content->content.secret_key,sizeof skey);
	skey_found=ops_true;
	return OPS_KEEP_MEMORY;
	}

    return OPS_RELEASE_MEMORY;
    }
    
static void get_key(const char *keyfile)
    {
    ops_reader_fd_arg_t arg;
    ops_parse_options_t opt;

    ops_parse_options_init(&opt);
    opt.cb=callback;

    arg.fd=open(keyfile,O_RDONLY);
    assert(arg.fd >= 0);
    opt.reader_arg=&arg;
    opt.reader=ops_reader_fd;

    ops_parse(&opt);

    assert(skey_found);
    }

int main(int argc,char **argv)
    {
    ops_writer_fd_arg_t arg;
    ops_create_options_t opt;
    ops_create_signature_t sig;
    ops_user_id_t id;
    unsigned char keyid[OPS_KEY_ID_SIZE];
    char *user_id; /* not const coz we use _fast_ */
    const char *keyfile;

    if(argc != 3)
	{
	fprintf(stderr,"%s <secret key file> <user_id>\n",argv[0]);
	exit(1);
	}

    keyfile=argv[1];
    user_id=argv[2];

    ops_init();

    get_key(keyfile);

    arg.fd=1;
    opt.writer=ops_writer_fd;
    opt.arg=&arg;

    ops_write_struct_public_key(&skey.public_key,&opt);

    ops_fast_create_user_id(&id,user_id);
    ops_write_struct_user_id(&id,&opt);

    ops_signature_start(&sig,&skey.public_key,&id,OPS_CERT_POSITIVE);
    ops_signature_add_creation_time(&sig,time(NULL));

    ops_keyid(keyid,&skey.public_key);
    ops_signature_add_issuer_key_id(&sig,keyid);

    ops_signature_add_primary_user_id(&sig,ops_true);

    ops_signature_hashed_subpackets_end(&sig);

    ops_write_signature(&sig,&skey.public_key,&skey,&opt);

    ops_secret_key_free(&skey);

    ops_finish();

    return 0;
    }
