/** \file
 */

#include <openpgpsdk/packet.h>
#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/util.h>
#include <openpgpsdk/accumulate.h>
#include "keyring_local.h"
#include "parse_local.h"
#include <openpgpsdk/signature.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <openpgpsdk/final.h>

typedef struct
    {
    ops_keyring_t *keyring;
    } accumulate_arg_t;

/**
 * \ingroup Callbacks
 */
static ops_parse_cb_return_t
accumulate_cb(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    accumulate_arg_t *arg=ops_parse_cb_get_arg(cbinfo);
    const ops_parser_content_union_t *content=&content_->content;
    ops_keyring_t *keyring=arg->keyring;
    ops_keydata_t *cur=NULL;
    const ops_public_key_t *pkey;

    if(keyring->nkeys >= 0)
	cur=&keyring->keys[keyring->nkeys];

    switch(content_->tag)
	{
    case OPS_PTAG_CT_PUBLIC_KEY:
    case OPS_PTAG_CT_SECRET_KEY:
    case OPS_PTAG_CT_ENCRYPTED_SECRET_KEY:
	//	printf("New key\n");
	++keyring->nkeys;
	EXPAND_ARRAY(keyring,keys);

	if(content_->tag == OPS_PTAG_CT_PUBLIC_KEY)
	    pkey=&content->public_key;
	else
	    pkey=&content->secret_key.public_key;

	memset(&keyring->keys[keyring->nkeys],'\0',
	       sizeof keyring->keys[keyring->nkeys]);

	ops_keyid(keyring->keys[keyring->nkeys].key_id,pkey);
	ops_fingerprint(&keyring->keys[keyring->nkeys].fingerprint,pkey);

	keyring->keys[keyring->nkeys].type=content_->tag;

	if(content_->tag == OPS_PTAG_CT_PUBLIC_KEY)
	    keyring->keys[keyring->nkeys].key.pkey=*pkey;
	else
	    keyring->keys[keyring->nkeys].key.skey=content->secret_key;
	return OPS_KEEP_MEMORY;

    case OPS_PTAG_CT_USER_ID:
	//	printf("User ID: %s\n",content->user_id.user_id);
	assert(cur);
    ops_add_userid_to_keydata(cur, &content->user_id);
	return OPS_KEEP_MEMORY;

    case OPS_PARSER_PACKET_END:
	if(!cur)
	    return OPS_RELEASE_MEMORY;
    ops_add_packet_to_keydata(cur, &content->packet);
	return OPS_KEEP_MEMORY;

    case OPS_PARSER_ERROR:
	fprintf(stderr,"Error: %s\n",content->error.error);
	assert(0);
	break;

    case OPS_PARSER_ERRCODE:
	switch(content->errcode.errcode)
	    {
	default:
	    fprintf(stderr,"parse error: %s\n",
		    ops_errcode(content->errcode.errcode));
	    assert(0);
	    }
	break;

    default:
	break;
	}

    // XXX: we now exclude so many things, we should either drop this or
    // do something to pass on copies of the stuff we keep
    return ops_parse_stacked_cb(content_,cbinfo);
    }

/**
 * \ingroup Parse
 *
 * Parse packets from an input stream until EOF or error.
 *
 * Key data found in the parsed data is added to #keyring.
 *
 * \param keyring Pointer to an existing keyring
 * \param opt Options to use when parsing
*/

int ops_parse_and_accumulate(ops_keyring_t *keyring,
			      ops_parse_info_t *parse_info)
    {
    int rtn;

    accumulate_arg_t arg;

    assert(!parse_info->rinfo.accumulate);

    memset(&arg,'\0',sizeof arg);

    arg.keyring=keyring;
    /* Kinda weird, but to do with counting, and we put it back after */
    --keyring->nkeys;

    ops_parse_cb_push(parse_info,accumulate_cb,&arg);

    parse_info->rinfo.accumulate=ops_true;

    rtn=ops_parse(parse_info);
    ++keyring->nkeys;

    return rtn;
    }

static void dump_one_keydata(const ops_keydata_t *key)
    {
    unsigned n;

    printf("Key ID: ");
    hexdump(key->key_id,8);

    printf("\nFingerpint: ");
    hexdump(key->fingerprint.fingerprint,key->fingerprint.length);

    printf("\n\nUIDs\n====\n\n");
    for(n=0 ; n < key->nuids ; ++n)
	printf("%s\n",key->uids[n].user_id);

    printf("\nPackets\n=======\n");
    for(n=0 ; n < key->npackets ; ++n)
	{
	printf("\n%03d: ",n);
	hexdump(key->packets[n].raw,key->packets[n].length);
	}
    printf("\n\n");
    }

// XXX: note necessarily a maintained part of the API.
/** ops_dump_keyring
    \todo decide whether this is part of the API or not
*/
void ops_dump_keyring(const ops_keyring_t *keyring)
    {
    int n;

    for(n=0 ; n < keyring->nkeys ; ++n)
	dump_one_keydata(&keyring->keys[n]);
    }
