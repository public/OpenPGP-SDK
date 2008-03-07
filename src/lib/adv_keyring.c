/** \file
 */

#include <openpgpsdk/keyring.h>
#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/util.h>
#include <openpgpsdk/accumulate.h>
#include <openpgpsdk/validate.h>
#include "keyring_local.h"
#include "parse_local.h"

#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#include <termios.h>
#endif
#include <fcntl.h>
#include <assert.h>

#include <openpgpsdk/final.h>

void ops_keydata_free(ops_keydata_t *key)
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
ops_get_public_key_from_data(const ops_keydata_t *data)
    {
    if(data->type == OPS_PTAG_CT_PUBLIC_KEY)
	return &data->key.pkey;
    return &data->key.skey.public_key;
    }

ops_boolean_t ops_key_is_secret(const ops_keydata_t *data)
    { return data->type != OPS_PTAG_CT_PUBLIC_KEY; }

const ops_secret_key_t *
ops_get_secret_key_from_data(const ops_keydata_t *data)
    {
    if(data->type != OPS_PTAG_CT_SECRET_KEY)
        return NULL;
    return &data->key.skey;
    }

static void echo_off()
    {
#ifndef WIN32
    struct termios term;
    int r;

    r=tcgetattr(0,&term);
    if(r < 0 && errno == ENOTTY)
	return;
    assert(r >= 0);

    term.c_lflag &= ~ECHO;

    r=tcsetattr(0,TCSANOW,&term);
    assert(r >= 0);
#endif
    }
	
static void echo_on()
    {
#ifndef WIN32
    struct termios term;
    int r;

    r=tcgetattr(0,&term);
    if(r < 0 && errno == ENOTTY)
	return;
    assert(r >= 0);

    term.c_lflag |= ECHO;

    r=tcsetattr(0,TCSANOW,&term);
    assert(r >= 0);
#endif
    }

char *ops_malloc_passphrase(char *pp)
    {
    char *passphrase;
    size_t n;

    n=strlen(pp);
    passphrase=malloc(n+1);
    strcpy(passphrase,pp);

    return passphrase;
    }

char *ops_get_passphrase(void)
    {
    char buffer[1024];
    size_t n;

    printf("Passphrase: ");
    
    echo_off();
    fgets(buffer,sizeof buffer,stdin);
    echo_on();

    putchar('\n');

    n=strlen(buffer);
    if(n && buffer[n-1] == '\n')
	buffer[--n]='\0';
    return ops_malloc_passphrase(buffer);
    }

typedef struct
    {
    const ops_keydata_t *key;
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
    case OPS_PTAG_CT_SIGNATURE_HEADER:
    case OPS_PTAG_CT_SIGNATURE_FOOTER:
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

 case OPS_PARSER_PACKET_END:
     // nothing to do
     break;

    default:
	fprintf(stderr,"Unexpected tag %d (0x%x)\n",content_->tag,
		content_->tag);
	assert(0);
	}

 done:
    return OPS_RELEASE_MEMORY;
    }

ops_secret_key_t *ops_decrypt_secret_key_from_data(const ops_keydata_t *key,
						   const char *pphrase)
    {
    ops_parse_info_t *pinfo;
    decrypt_arg_t arg;

    memset(&arg,'\0',sizeof arg);
    arg.key=key;
    arg.pphrase=strdup(pphrase);

    pinfo=ops_parse_info_new();

    ops_keydata_reader_set(pinfo,key);
    ops_parse_cb_set(pinfo,decrypt_cb,&arg);
    pinfo->rinfo.accumulate=ops_true;

    ops_parse(pinfo);

    return arg.skey;
    }

void ops_set_secret_key(ops_parser_content_union_t* content,const ops_keydata_t *key)
    {
    *content->get_secret_key.secret_key=&key->key.skey;
    }

const unsigned char* ops_get_key_id(const ops_keydata_t *key)
    {
    return key->key_id;
    }

unsigned ops_get_user_id_count(const ops_keydata_t *key)
    {
    return key->nuids;
    }

const unsigned char* ops_get_user_id(const ops_keydata_t *key, unsigned index)
    {
    return key->uids[index].user_id;
    }

ops_boolean_t ops_key_is_supported(const ops_keydata_t *key)
    {
    if ( key->type == OPS_PTAG_CT_PUBLIC_KEY ) {
        if ( key->key.pkey.algorithm == OPS_PKA_RSA ) {
            return ops_true;
        }
    } else if ( key->type == OPS_PTAG_CT_PUBLIC_KEY ) {
        if ( key->key.skey.algorithm == OPS_PKA_RSA ) {
            return ops_true;
        }
    }
    return ops_false;
    }


const ops_keydata_t* ops_keyring_get_key(const ops_keyring_t *keyring, int index)
    {
    return &keyring->keys[index]; 
    }

// \todo document OPS keyring format

// eof
