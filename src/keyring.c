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

ops_key_data_t *
ops_keyring_find_key_by_id(const ops_keyring_t *keyring,
			   const unsigned char keyid[OPS_KEY_ID_SIZE])
    {
    int n;

    for(n=0 ; n < keyring->nkeys ; ++n)
	if(!memcmp(keyring->keys[n].keyid,keyid,OPS_KEY_ID_SIZE))
	    return &keyring->keys[n];

    return NULL;
    }

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

/**
 * \ingroup Memory
 *
 * ops_keyring_free() frees the memory used in one ops_keyring_t structure
 * \param keyring Keyring to be freed.
 */
void ops_keyring_free(ops_keyring_t *keyring)
    {
    int n;

    for(n=0 ; n < keyring->nkeys ; ++n)
	ops_key_data_free(&keyring->keys[n]);
    free(keyring->keys);
    keyring->keys=NULL;
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

static ops_parse_cb_return_t
cb_keyring_read(const ops_parser_content_t *content_,
		ops_parse_cb_info_t *cbinfo)
    {
    //    const ops_parser_content_union_t *content=&content_->content;
    //    char buffer[1024];
    //    size_t n;

    OPS_USED(cbinfo);

    switch(content_->tag)
	{
    case OPS_PARSER_PTAG:
    case OPS_PTAG_CT_ENCRYPTED_SECRET_KEY: // we get these because we didn't prompt
    case OPS_PTAG_CT_SIGNATURE_HEADER:
    case OPS_PTAG_CT_SIGNATURE_FOOTER:
    case OPS_PTAG_CT_SIGNATURE:
    case OPS_PTAG_CT_TRUST:
    case OPS_PARSER_ERRCODE:
	break;

    case OPS_PARSER_CMD_GET_SK_PASSPHRASE:
	// we don't want to prompt when reading the keyring
	break;

    default:
	fprintf(stderr,"Unexpected packet tag=%d (0x%x)\n",content_->tag,
		content_->tag);
	assert(0);
	exit(1);
	}

    return OPS_RELEASE_MEMORY;
    }

/* Read a keyring from a file (either public or secret) */
void ops_keyring_read(ops_keyring_t *keyring,const char *file)
    {
    ops_parse_info_t *pinfo;
    int fd;

    memset(keyring,'\0',sizeof *keyring);

    pinfo=ops_parse_info_new();

    fd=open(file,O_RDONLY);
    if(fd < 0)
	{
	perror(file);
	exit(1);
	}

    ops_reader_set_fd(pinfo,fd);

    ops_parse_cb_set(pinfo,cb_keyring_read,NULL);

    ops_parse_and_accumulate(keyring,pinfo);

    close(fd);

    ops_parse_info_delete(pinfo);
    }

char *ops_get_passphrase(void)
    {
    char buffer[1024];
    char *passphrase;
    size_t n;

    printf("Passphrase: ");
    fgets(buffer,sizeof buffer,stdin);
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

