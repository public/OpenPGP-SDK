#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/packet-show.h>
#include <openpgpsdk/keyring.h>
#include "keyring_local.h"
#include <openpgpsdk/util.h>
#include <openpgpsdk/signature.h>
#include <openpgpsdk/memory.h>
#include <openpgpsdk/validate.h>
#include <assert.h>
#include <string.h>

#include <openpgpsdk/final.h>

static int debug=0;

static ops_boolean_t check_binary_signature(const unsigned len,
                                            const unsigned char *data,
                                            const ops_signature_t *sig, 
                                            const ops_public_key_t *signer __attribute__((unused)))
    {
    // Does the signed hash match the given hash?

    int n=0;
    ops_hash_t hash;
    unsigned char hashout[OPS_MAX_HASH_SIZE];
    unsigned char trailer[6];
    unsigned int hashedlen;

    //common_init_signature(&hash,sig);
    ops_hash_any(&hash,sig->hash_algorithm);
    hash.init(&hash);
    hash.add(&hash,data,len);
    hash.add(&hash,sig->v4_hashed_data,sig->v4_hashed_data_length);

    trailer[0]=0x04; // version
    trailer[1]=0xFF;
    hashedlen=sig->v4_hashed_data_length;
    trailer[2]=hashedlen >> 24;
    trailer[3]=hashedlen >> 16;
    trailer[4]=hashedlen >> 8;
    trailer[5]=hashedlen;
    hash.add(&hash,&trailer[0],6);

    n=hash.finish(&hash,hashout);

    //    return ops_false;
    return ops_check_signature(hashout,n,sig,signer);
    }

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

ops_parse_cb_return_t
validate_key_cb(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    const ops_parser_content_union_t *content=&content_->content;
    validate_key_cb_arg_t *arg=ops_parse_cb_get_arg(cbinfo);
    ops_error_t **errors=ops_parse_cb_get_errors(cbinfo);
    const ops_key_data_t *signer;
    ops_boolean_t valid=ops_false;

    if (debug)
        printf("%s\n",ops_show_packet_tag(content_->tag));

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
	arg->last_seen=ID;
	return OPS_KEEP_MEMORY;

    case OPS_PTAG_CT_USER_ATTRIBUTE:
	assert(content->user_attribute.data.len);
	printf("user attribute, length=%d\n",(int)content->user_attribute.data.len);
	if(arg->user_attribute.data.len)
	    ops_user_attribute_free(&arg->user_attribute);
	arg->user_attribute=content->user_attribute;
	arg->last_seen=ATTRIBUTE;
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
	    if(arg->last_seen == ID)
		valid=ops_check_user_id_certification_signature(&arg->pkey,
								&arg->user_id,
								&content->signature,
								ops_get_public_key_from_data(signer),
								arg->rarg->key->packets[arg->rarg->packet].raw);
	    else
		valid=ops_check_user_attribute_certification_signature(&arg->pkey,
								       &arg->user_attribute,
								       &content->signature,
								       ops_get_public_key_from_data(signer),
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

#ifdef MOVED
    case OPS_SIG_TEXT:
#endif
    case OPS_SIG_STANDALONE:
    case OPS_SIG_PRIMARY:
    case OPS_SIG_REV_KEY:
    case OPS_SIG_REV_SUBKEY:
    case OPS_SIG_TIMESTAMP:
    case OPS_SIG_3RD_PARTY:
        OPS_ERROR_1(errors, OPS_E_UNIMPLEMENTED,
                    "Verification of signature type 0x%02x not yet implemented\n", content->signature.type);
                    break;

	default:
            OPS_ERROR_1(errors, OPS_E_UNIMPLEMENTED,
                    "Unexpected signature type 0x%02x\n", content->signature.type);
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

	// ignore these
    case OPS_PARSER_PTAG:
    case OPS_PTAG_CT_SIGNATURE_HEADER:
    case OPS_PTAG_CT_SIGNATURE:
	break;

    default:
	fprintf(stderr,"unexpected tag=0x%x\n",content_->tag);
	assert(0);
	break;
	}
    return OPS_RELEASE_MEMORY;
    }

ops_parse_cb_return_t
validate_data_cb(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    const ops_parser_content_union_t *content=&content_->content;
    validate_data_cb_arg_t *arg=ops_parse_cb_get_arg(cbinfo);
    ops_error_t **errors=ops_parse_cb_get_errors(cbinfo);
    const ops_key_data_t *signer;
    ops_boolean_t valid=ops_false;
    //    unsigned len=0;
    //    unsigned char *data=NULL;
    ops_memory_t* mem=NULL;

    if (debug)
        printf("%s\n",ops_show_packet_tag(content_->tag));

    switch(content_->tag)
	{
    case OPS_PTAG_CT_SIGNED_CLEARTEXT_HEADER:
        // ignore - this gives us the "Armor Header" line "Hash: SHA1" or similar
        break;

    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
        // ignore
        break;

    case OPS_PTAG_CT_LITERAL_DATA_BODY:
        arg->data.literal_data_body=content->literal_data_body;
        arg->use=LITERAL_DATA;
        return OPS_KEEP_MEMORY;
        break;

    case OPS_PTAG_CT_SIGNED_CLEARTEXT_BODY:
        arg->data.signed_cleartext_body=content->signed_cleartext_body;
        arg->use=SIGNED_CLEARTEXT;
        return OPS_KEEP_MEMORY;
        break;

    case OPS_PTAG_CT_SIGNED_CLEARTEXT_TRAILER:
        // this gives us an ops_hash_t struct
        break;

    case OPS_PTAG_CT_SIGNATURE: // V3 sigs
        // this gives us a signature struct with all info about hash alg, etc from the packet
        break;

    case OPS_PTAG_CT_SIGNATURE_FOOTER: // V4 sigs
        
        if (debug)
            {
            printf("\n*** hashed data:\n");
            unsigned int zzz=0;
            for (zzz=0; zzz<content->signature.v4_hashed_data_length; zzz++)
                printf("0x%02x ", content->signature.v4_hashed_data[zzz]);
            printf("\n");
            printf("  type=%02x signer_id=",content->signature.type);
            hexdump(content->signature.signer_id,
                    sizeof content->signature.signer_id);
            }

        signer=ops_keyring_find_key_by_id(arg->keyring,
                                          content->signature.signer_id);
        if(!signer)
            {
            OPS_ERROR(errors,OPS_E_V_UNKNOWN_SIGNER,"Unknown Signer");
            printf(" UNKNOWN SIGNER\n");
            ++arg->result->unknown_signer_count;
            break;
            }
        
        mem=ops_memory_new();
        ops_memory_init(mem,128);
        
        switch(content->signature.type)
            {
        case OPS_SIG_BINARY:
        case OPS_SIG_TEXT:
            switch(arg->use)
                {
            case LITERAL_DATA:
                ops_memory_add(mem,
                               arg->data.literal_data_body.data,
                               arg->data.literal_data_body.length);
                break;

            case SIGNED_CLEARTEXT:
                ops_memory_add(mem,
                               arg->data.signed_cleartext_body.data,
                               arg->data.signed_cleartext_body.length);
                break;

            default:
                OPS_ERROR_1(errors,OPS_E_UNIMPLEMENTED,"Unimplemented Sig Use %d", arg->use);
                printf(" Unimplemented Sig Use %d\n", arg->use);
                break;
                }

            valid=check_binary_signature(ops_memory_get_length(mem), 
                                         ops_memory_get_data(mem),
                                         &content->signature,
                                         ops_get_public_key_from_data(signer));
            break;

        OPS_ERROR_1(errors, OPS_E_UNIMPLEMENTED,
                    "Verification of signature type 0x%02x not yet implemented\n", content->signature.type);
                    break;

	default:
            OPS_ERROR_1(errors, OPS_E_UNIMPLEMENTED,
                    "Unexpected signature type 0x%02x\n", content->signature.type);
            //	    exit(1);
	    }
    ops_memory_free(mem);

	if(valid)
	    {
	    ++arg->result->valid_count;
	    }
	else
	    {
        OPS_ERROR(errors,OPS_E_V_BAD_SIGNATURE,"Bad Signature");
	    printf(" BAD SIGNATURE\n");
	    ++arg->result->invalid_count;
	    }
	break;

	// ignore these
    case OPS_PARSER_PTAG:
    case OPS_PTAG_CT_SIGNATURE_HEADER:
        //    case OPS_PTAG_CT_SIGNATURE:
	break;

    default:
	fprintf(stderr,"unexpected tag=0x%x\n",content_->tag);
	assert(0);
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

/* 
 * Validate all signatures on a single key against the given keyring
 */
static void validate_key_signatures(ops_validate_result_t *result,const ops_key_data_t *key,
				    const ops_keyring_t *keyring)
    {
    ops_parse_info_t *pinfo;
    validate_key_cb_arg_t carg;

    memset(&carg,'\0',sizeof carg);
    carg.result=result;

    pinfo=ops_parse_info_new();
    //    ops_parse_options(&opt,OPS_PTAG_CT_SIGNATURE,OPS_PARSE_PARSED);

    carg.keyring=keyring;

    ops_parse_cb_set(pinfo,validate_key_cb,&carg);
    ops_key_data_reader_set(pinfo,key);

    carg.rarg=ops_reader_get_arg_from_pinfo(pinfo);

    ops_parse(pinfo);

    ops_public_key_free(&carg.pkey);
    if(carg.subkey.version)
	ops_public_key_free(&carg.subkey);
    ops_user_id_free(&carg.user_id);
    ops_user_attribute_free(&carg.user_attribute);

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
