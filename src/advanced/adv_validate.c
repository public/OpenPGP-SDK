#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/keyring.h>
#include "keyring_local.h"
#include <openpgpsdk/util.h>
#include <openpgpsdk/signature.h>
#include <openpgpsdk/validate.h>
#include <assert.h>
#include <string.h>

#include <openpgpsdk/final.h>

typedef struct
    {
    const ops_key_data_t *key;
    unsigned packet;
    unsigned offset;
    } validate_reader_arg_t;

typedef struct
    {
    ops_public_key_t pkey;
    ops_public_key_t subkey;
    ops_user_id_t user_id;
    const ops_keyring_t *keyring;
    validate_reader_arg_t *rarg;
    ops_validate_result_t *result;
    } validate_cb_arg_t;

static int key_data_reader(void *dest,size_t length,ops_error_t **errors,
			   ops_reader_info_t *rinfo,
			   ops_parse_cb_info_t *cbinfo)
    {
    validate_reader_arg_t *arg=ops_reader_get_arg(rinfo);

    OPS_USED(errors);
    OPS_USED(cbinfo);
    if(arg->offset == arg->key->packets[arg->packet].length)
	{
	++arg->packet;
	arg->offset=0;
	}

    if(arg->packet == arg->key->npackets)
	return 0;

    // we should never be asked to cross a packet boundary in a single read
    assert(arg->key->packets[arg->packet].length >= arg->offset+length);

    memcpy(dest,&arg->key->packets[arg->packet].raw[arg->offset],length);
    arg->offset+=length;

    return length;
    }

/**
 * \ingroup Callbacks
 */

static ops_parse_cb_return_t
validate_cb(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    const ops_parser_content_union_t *content=&content_->content;
    validate_cb_arg_t *arg=ops_parse_cb_get_arg(cbinfo);
    const ops_key_data_t *signer;
    ops_boolean_t valid;

    switch(content_->tag)
	{
    case OPS_PTAG_CT_PUBLIC_KEY:
	assert(arg->pkey.version == 0);
	arg->pkey=content->public_key;
	return OPS_KEEP_MEMORY;

    case OPS_PTAG_CT_PUBLIC_SUBKEY:
	if(arg->subkey.version)
	    ops_public_key_free(&arg->subkey);
	arg->subkey=content->public_key;
	return OPS_KEEP_MEMORY;

    case OPS_PTAG_CT_USER_ID:
	printf("user id=%s\n",content->user_id.user_id);
	if(arg->user_id.user_id)
	    ops_user_id_free(&arg->user_id);
	arg->user_id=content->user_id;
	return OPS_KEEP_MEMORY;

    case OPS_PTAG_CT_SIGNATURE_FOOTER:
	printf("  type=%02x signer_id=",content->signature.type);
	hexdump(content->signature.signer_id,
		sizeof content->signature.signer_id);

	signer=ops_keyring_find_key_by_id(arg->keyring,
					   content->signature.signer_id);
	if(!signer)
	    {
	    printf(" UNKNOWN SIGNER\n");
	    ++arg->result->unknown_signer_count;
	    break;
	    }

	switch(content->signature.type)
	    {
	case OPS_CERT_GENERIC:
	case OPS_CERT_PERSONA:
	case OPS_CERT_CASUAL:
	case OPS_CERT_POSITIVE:
	case OPS_SIG_REV_CERT:
	    valid=ops_check_certification_signature(&arg->pkey,&arg->user_id,
		    &content->signature,ops_get_public_key_from_data(signer),
		    arg->rarg->key->packets[arg->rarg->packet].raw);
	    break;

	case OPS_SIG_SUBKEY:
	    // XXX: we should also check that the signer is the key we are validating, I think.
	    valid=ops_check_subkey_signature(&arg->pkey,&arg->subkey,
	     	    &content->signature,
		    ops_get_public_key_from_data(signer),
		    arg->rarg->key->packets[arg->rarg->packet].raw);
	    break;

	case OPS_SIG_DIRECT:
	    valid=ops_check_direct_signature(&arg->pkey,&content->signature,
		    ops_get_public_key_from_data(signer),
		    arg->rarg->key->packets[arg->rarg->packet].raw);
	    break;

	default:
	    fprintf(stderr,"Unexpected signature type=0x%02x\n",
		    content->signature.type);
	    exit(1);
	    }
	if(valid)
	    {
	    printf(" validated\n");
	    ++arg->result->valid_count;
	    }
	else
	    {
	    printf(" BAD SIGNATURE\n");
	    ++arg->result->invalid_count;
	    }
	break;

    default:
	// XXX: reinstate when we can make packets optional
	//	fprintf(stderr,"unexpected tag=%d\n",content_->tag);
	break;
	}
    return OPS_RELEASE_MEMORY;
    }

static void key_data_destroyer(ops_reader_info_t *rinfo)
    { free(ops_reader_get_arg(rinfo)); }

void ops_key_data_reader_set(ops_parse_info_t *pinfo,const ops_key_data_t *key)
    {
    validate_reader_arg_t *arg=malloc(sizeof *arg);

    memset(arg,'\0',sizeof *arg);

    arg->key=key;
    arg->packet=0;
    arg->offset=0;

    ops_reader_set(pinfo,key_data_reader,key_data_destroyer,arg);
    }

static void validate_key_signatures(ops_validate_result_t *result,const ops_key_data_t *key,
				    const ops_keyring_t *keyring)
    {
    ops_parse_info_t *pinfo;
    validate_cb_arg_t carg;

    memset(&carg,'\0',sizeof carg);
    carg.result=result;

    pinfo=ops_parse_info_new();
    //    ops_parse_options(&opt,OPS_PTAG_CT_SIGNATURE,OPS_PARSE_PARSED);

    carg.keyring=keyring;

    ops_parse_cb_set(pinfo,validate_cb,&carg);
    ops_key_data_reader_set(pinfo,key);

    carg.rarg=ops_reader_get_arg_from_pinfo(pinfo);

    ops_parse(pinfo);

    ops_public_key_free(&carg.pkey);
    if(carg.subkey.version)
	ops_public_key_free(&carg.subkey);
    ops_user_id_free(&carg.user_id);

    ops_parse_info_delete(pinfo);
    }

void ops_validate_all_signatures(ops_validate_result_t *result,
				 const ops_keyring_t *ring)
    {
    int n;

    memset(result,'\0',sizeof *result);
    for(n=0 ; n < ring->nkeys ; ++n)
	validate_key_signatures(result,&ring->keys[n],ring);
    }
