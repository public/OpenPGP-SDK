/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. 
 * 
 * You may obtain a copy of the License at 
 *     http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** \file
 */

#include <openpgpsdk/keyring.h>
#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/util.h>
#include <openpgpsdk/accumulate.h>
#include <openpgpsdk/validate.h>
#include <openpgpsdk/signature.h>
#include <openpgpsdk/readerwriter.h>
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
    key->nuids=0;

    for(n=0 ; n < key->npackets ; ++n)
	ops_packet_free(&key->packets[n]);
    free(key->packets);
    key->packets=NULL;
    key->npackets=0;

    if(key->type == OPS_PTAG_CT_PUBLIC_KEY)
	ops_public_key_free(&key->key.pkey);
    else
	ops_secret_key_free(&key->key.skey);

    free(key);
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

ops_secret_key_t *
ops_get_writable_secret_key_from_data(ops_keydata_t *data)
    {
    if (data->type != OPS_PTAG_CT_SECRET_KEY)
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

// \todo check where userid pointers are copied
void ops_copy_userid(ops_user_id_t* dst, const ops_user_id_t* src)
    {
    int len=strlen((char *)src->user_id);
    if (dst->user_id)
        free(dst->user_id);
    dst->user_id=ops_mallocz(len+1);

    memcpy(dst->user_id, src->user_id, len);
    }

// \todo check where pkt pointers are copied
void ops_copy_packet(ops_packet_t* dst, const ops_packet_t* src)
    {
    if (dst->raw)
        free(dst->raw);
    dst->raw=ops_mallocz(src->length);

    dst->length=src->length;
    memcpy(dst->raw, src->raw, src->length);
    }

ops_user_id_t* ops_add_userid_to_keydata(ops_keydata_t* keydata, const ops_user_id_t* userid)
    {
    ops_user_id_t* new_uid=NULL;

    EXPAND_ARRAY(keydata, uids);

    // initialise new entry in array
    new_uid=&keydata->uids[keydata->nuids];

    //    keydata->uids[keydata->nuids].user_id=NULL;
    new_uid->user_id=NULL;

    // now copy it
    //    ops_copy_userid(&keydata->uids[keydata->nuids],userid);
    ops_copy_userid(new_uid,userid);
    keydata->nuids++;

    return new_uid;
    }

ops_packet_t* ops_add_packet_to_keydata(ops_keydata_t* keydata, const ops_packet_t* packet)
    {
    ops_packet_t* new_pkt=NULL;

    EXPAND_ARRAY(keydata, packets);

    // initialise new entry in array
    new_pkt=&keydata->packets[keydata->npackets];
    new_pkt->length=0;
    new_pkt->raw=NULL;

    // now copy it
    ops_copy_packet(new_pkt, packet);
    keydata->npackets++;

    return new_pkt;
    }

void ops_add_signed_userid_to_keydata(ops_keydata_t* keydata, const ops_user_id_t* user_id, const ops_packet_t* sigpacket)
    {
    //int i=0;
    ops_user_id_t * uid=NULL;
    ops_packet_t * pkt=NULL;

    uid=ops_add_userid_to_keydata(keydata, user_id);
    pkt=ops_add_packet_to_keydata(keydata, sigpacket);

    /*
     * add entry in sigs array to link the userid and sigpacket
     */

    // and add ptr to it from the sigs array
    EXPAND_ARRAY(keydata, sigs);

    // setup new entry in array

    keydata->sigs[keydata->nsigs].userid=uid;
    keydata->sigs[keydata->nsigs].packet=pkt;

    keydata->nsigs++;
    }

ops_boolean_t ops_add_selfsigned_userid_to_keydata(ops_keydata_t* keydata, ops_user_id_t* userid)
    {
    ops_packet_t sigpacket;

    ops_memory_t* mem_userid=NULL;
    ops_create_info_t* cinfo_userid=NULL;

    ops_memory_t* mem_sig=NULL;
    ops_create_info_t* cinfo_sig=NULL;

    ops_create_signature_t *sig=NULL;
    //    unsigned char keyid[OPS_KEY_ID_SIZE];

    /*
     * create signature packet for this userid
     */

    // create userid pkt
    ops_setup_memory_write(&cinfo_userid, &mem_userid, 128);
    ops_write_struct_user_id(userid, cinfo_userid);

    // create sig for this pkt

    sig=ops_create_signature_new();
    ops_signature_start_key_signature(sig, &keydata->key.skey.public_key, userid, OPS_CERT_POSITIVE);
    ops_signature_add_creation_time(sig,time(NULL));
    ops_signature_add_issuer_key_id(sig,keydata->key_id);
    ops_signature_add_primary_user_id(sig, ops_true);
    ops_signature_hashed_subpackets_end(sig);

    ops_setup_memory_write(&cinfo_sig, &mem_sig, 128);
    ops_write_signature(sig,&keydata->key.skey.public_key,&keydata->key.skey, cinfo_sig);

    // add this packet to keydata

    sigpacket.length=ops_memory_get_length(mem_sig);
    sigpacket.raw=ops_memory_get_data(mem_sig);
    //    pkt=ops_add_packet_to_keydata(keydata, &packet);
    //    ops_add_signature_to_keydata(keydata, keydata->key_id, packet);

    // add userid to keydata
    ops_add_signed_userid_to_keydata(keydata, userid, &sigpacket);

    // cleanup
    ops_create_signature_delete(sig);
    ops_create_info_delete(cinfo_userid);
    ops_create_info_delete(cinfo_sig);
    ops_memory_free(mem_userid);
    ops_memory_free(mem_sig);

    return ops_true;
    }

ops_keydata_t *ops_keydata_new(void)
    { return ops_mallocz(sizeof(ops_keydata_t)); }

void ops_keydata_init(ops_keydata_t* keydata, const ops_content_tag_t type)
    {
    assert(keydata->type==OPS_PTAG_CT_RESERVED);
    assert(type==OPS_PTAG_CT_PUBLIC_KEY || type==OPS_PTAG_CT_SECRET_KEY);

    keydata->type=type;
    }

// eof
