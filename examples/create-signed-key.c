#include "common.h"
#include <openpgpsdk/create.h>
#include <openpgpsdk/util.h>
#include <openpgpsdk/signature.h>
#include <openpgpsdk/packet-parse.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>

/*
 * Slightly strange beast that might get replaced later - it needs
 * some other OpenPGP package to generate a key for it to use - this
 * is because we don't have a way to generate our own (yet).
 */

int main(int argc,char **argv)
    {
    ops_writer_fd_arg_t arg;
    ops_create_options_t opt;
    ops_create_signature_t sig;
    ops_user_id_t id;
    unsigned char keyid[OPS_KEY_ID_SIZE];
    unsigned char *user_id; /* not const coz we use _fast_ */
    const char *keyfile;
    ops_secret_key_t *skey;


    if(argc != 3)
	{
	fprintf(stderr,"%s <secret key file> <user_id>\n",argv[0]);
	exit(1);
	}

    keyfile=argv[1];
    user_id=(unsigned char *)argv[2];

    ops_init();

    skey=get_key(keyfile);
    assert(skey);

    arg.fd=1;
    opt.writer=ops_writer_fd;
    opt.arg=&arg;

    ops_write_struct_public_key(&skey->public_key,&opt);

    ops_fast_create_user_id(&id,user_id);
    ops_write_struct_user_id(&id,&opt);

    ops_signature_start(&sig,&skey->public_key,&id,OPS_CERT_POSITIVE);
    ops_signature_add_creation_time(&sig,time(NULL));

    ops_keyid(keyid,&skey->public_key);
    ops_signature_add_issuer_key_id(&sig,keyid);

    ops_signature_add_primary_user_id(&sig,ops_true);

    ops_signature_hashed_subpackets_end(&sig);

    ops_write_signature(&sig,&skey->public_key,skey,&opt);

    ops_secret_key_free(skey);

    ops_finish();

    return 0;
    }
