#include "create.h"
#include "util.h"
#include "signature.h"
#include <stdio.h>

int main(int argc,char **argv)
    {
    ops_writer_fd_arg_t arg;
    ops_create_options_t opt;
    char *user_id;
    const char *nstr;
    const char *estr;
    BIGNUM *n=NULL;
    BIGNUM *e=NULL;
    ops_public_key_t key;
    ops_secret_key_t skey;
    ops_create_signature_t sig;
    ops_user_id_t id;
    unsigned char keyid[OPS_KEY_ID_SIZE];

    if(argc != 2)
	{
	fprintf(stderr,"%s <public key file> <secret key file>\n",argv[0]);
	exit(1);
	}
    
    nstr=argv[1];
    estr=argv[2];
    user_id=argv[3];

    BN_hex2bn(&n,nstr);
    BN_hex2bn(&e,estr);

    arg.fd=1;
    opt.writer=ops_writer_fd;
    opt.arg=&arg;

    ops_fast_create_rsa_public_key(&key,time(NULL),n,e);
    ops_write_struct_public_key(&key,&opt);

    ops_fast_create_user_id(&id,user_id);
    ops_write_struct_user_id(&id,&opt);

    ops_signature_start(&sig,&key,&id);
    ops_signature_add_creation_time(&sig,time(NULL));

    ops_keyid(keyid,&key);
    ops_signature_add_issuer_key_id(&sig,keyid);

    ops_signature_add_primary_user_id(&sig,ops_true);

    ops_signature_hashed_subpackets_end(&sig);

    ops_signature_end(&sig,&key,&skey);

    return 0;
    }
