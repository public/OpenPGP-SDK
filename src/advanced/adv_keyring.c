/** \file
 */

#include <openpgpsdk/keyring.h>
#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/util.h>
#include <openpgpsdk/accumulate.h>
#include <openpgpsdk/validate.h>
#include "keyring_local.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <termios.h>

#include <openpgpsdk/final.h>

void ops_key_data_free(ops_key_data_t *key)
    {
    unsigned n;

    for(n=0 ; n < key->nuids ; ++n)
	ops_user_id_free(&key->uids[n]);
    free(key->uids);
    key->uids=NULL;

    for(n=0 ; n < key->npackets ; ++n)
	ops_packet_free(&key->packets[n]);
    free(key->packets);
    key->packets=NULL;

    if(key->type == OPS_PTAG_CT_PUBLIC_KEY)
	ops_public_key_free(&key->key.pkey);
    else
	ops_secret_key_free(&key->key.skey);
    }

const ops_public_key_t *
ops_get_public_key_from_data(const ops_key_data_t *data)
    {
    if(data->type == OPS_PTAG_CT_PUBLIC_KEY)
	return &data->key.pkey;
    return &data->key.skey.public_key;
    }

ops_boolean_t ops_key_is_secret(const ops_key_data_t *data)
    { return data->type != OPS_PTAG_CT_PUBLIC_KEY; }

const ops_secret_key_t *
ops_get_secret_key_from_data(const ops_key_data_t *data)
    {
    if(data->type != OPS_PTAG_CT_SECRET_KEY)
	return NULL;
    return &data->key.skey;
    }

static void echo_off()
    {
    struct termios term;
    int r;

    r=tcgetattr(0,&term);
    if(r < 0 && errno == ENOTTY)
	return;
    assert(r >= 0);

    term.c_lflag &= ~ECHO;

    r=tcsetattr(0,TCSANOW,&term);
    assert(r >= 0);
    }
	
static void echo_on()
    {
    struct termios term;
    int r;

    r=tcgetattr(0,&term);
    if(r < 0 && errno == ENOTTY)
	return;
    assert(r >= 0);

    term.c_lflag |= ECHO;

    r=tcsetattr(0,TCSANOW,&term);
    assert(r >= 0);
    }

char *ops_get_passphrase(void)
    {
    char buffer[1024];
    char *passphrase;
    size_t n;

    printf("Passphrase: ");

    echo_off();
    fgets(buffer,sizeof buffer,stdin);
    echo_on();

    putchar('\n');

    n=strlen(buffer);
    if(n && buffer[n-1] == '\n')
	buffer[--n]='\0';
    passphrase=malloc(n+1);
    strcpy(passphrase,buffer);

    return passphrase;
    }

typedef struct
    {
    ops_key_data_t *key;
    char *pphrase;
    ops_secret_key_t *skey;
    } decrypt_arg_t;

static ops_parse_cb_return_t decrypt_cb(const ops_parser_content_t *content_,
					ops_parse_cb_info_t *cbinfo)
    {
    const ops_parser_content_union_t *content=&content_->content;
    decrypt_arg_t *arg=ops_parse_cb_get_arg(cbinfo);

    OPS_USED(cbinfo);

    switch(content_->tag)
	{
    case OPS_PARSER_PTAG:
    case OPS_PTAG_CT_USER_ID:
    case OPS_PTAG_CT_SIGNATURE:
    case OPS_PTAG_CT_TRUST:
	break;

    case OPS_PARSER_CMD_GET_SK_PASSPHRASE:
	*content->secret_key_passphrase.passphrase=arg->pphrase;
	return OPS_KEEP_MEMORY;

    case OPS_PARSER_ERRCODE:
	switch(content->errcode.errcode)
	    {
	case OPS_E_P_MPI_FORMAT_ERROR:
	    /* Generally this means a bad passphrase */
	    fprintf(stderr,"Bad passphrase!\n");
	    goto done;

	case OPS_E_P_PACKET_CONSUMED:
	    /* And this is because of an error we've accepted */
	    goto done;

	default:
	    fprintf(stderr,"parse error: %s\n",
		    ops_errcode(content->errcode.errcode));
	    assert(0);
	    break;
	    }

	break;

    case OPS_PARSER_ERROR:
	printf("parse error: %s\n",content->error.error);
	assert(0);
	break;

    case OPS_PTAG_CT_SECRET_KEY:
	arg->skey=malloc(sizeof *arg->skey);
	*arg->skey=content->secret_key;
	return OPS_KEEP_MEMORY;

    default:
	fprintf(stderr,"Unexpected tag %d (0x%x)\n",content_->tag,
		content_->tag);
	assert(0);
	}

 done:
    return OPS_RELEASE_MEMORY;
    }

ops_secret_key_t *ops_decrypt_secret_key_from_data(ops_key_data_t *key,
						   const char *pphrase)
    {
    ops_parse_info_t *pinfo;
    decrypt_arg_t arg;

    memset(&arg,'\0',sizeof arg);
    arg.key=key;
    arg.pphrase=strdup(pphrase);

    pinfo=ops_parse_info_new();

    ops_key_data_reader_set(pinfo,key);
    ops_parse_cb_set(pinfo,decrypt_cb,&arg);

    ops_parse(pinfo);

    return arg.skey;
    }
