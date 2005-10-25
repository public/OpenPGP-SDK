/** \file
 */

#include <openpgpsdk/packet.h>
#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/util.h>
#include <openpgpsdk/accumulate.h>
#include "keyring_local.h"
#include <openpgpsdk/signature.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct
    {
    ops_packet_parse_callback_t *cb;
    void *cb_arg;
    ops_keyring_t *keyring;
    } accumulate_arg_t;

/**
 * \ingroup Callbacks
 */
static ops_parse_callback_return_t
accumulate_cb(const ops_parser_content_t *content_,void *arg_)
    {
    accumulate_arg_t *arg=arg_;
    const ops_parser_content_union_t *content=&content_->content;
    ops_keyring_t *keyring=arg->keyring;
    ops_key_data_t *cur=&keyring->keys[keyring->nkeys];

    switch(content_->tag)
	{
    case OPS_PTAG_CT_PUBLIC_KEY:
	//	printf("New key\n");
	++keyring->nkeys;
	EXPAND_ARRAY(keyring,keys);

	memset(&keyring->keys[keyring->nkeys],'\0',
	       sizeof keyring->keys[keyring->nkeys]);

	ops_keyid(keyring->keys[keyring->nkeys].keyid,&content->public_key);
	ops_fingerprint(&keyring->keys[keyring->nkeys].fingerprint,
			&content->public_key);

	keyring->keys[keyring->nkeys].pkey=content->public_key;
	return OPS_KEEP_MEMORY;

    case OPS_PTAG_CT_USER_ID:
	//	printf("User ID: %s\n",content->user_id.user_id);
	EXPAND_ARRAY(cur,uids);
	cur->uids[cur->nuids++]=content->user_id;
	return OPS_KEEP_MEMORY;

    case OPS_PARSER_PACKET_END:
	EXPAND_ARRAY(cur,packets);
	cur->packets[cur->npackets++]=content->packet;
	return OPS_KEEP_MEMORY;

    case OPS_PARSER_ERROR:
	fprintf(stderr,"Error: %s\n",content->error.error);
	break;

    default:
	break;
	}

    // XXX: we now exclude so many things, we should either drop this or
    // do something to pass on copies of the stuff we keep
    if(arg->cb)
	return arg->cb(content_,arg->cb_arg);
    return OPS_RELEASE_MEMORY;
    }

/**
 * \ingroup Parse
 *
 * ops_parse_and_accumulate() parses packets from an input stream until EOF or error.
 *
 * The parsed data is added to "keyring".
 *
 * Once all the input data has been parsed:
 * - the keyring is printed to stdout
 * - each signature on the keyring is validated, with the result printed to stdout
 *
 * \sa See Detailed Description for usage.
 *
 * \param *keyring Pointer to an existing keyring
 * \param *opt Options to use when parsing
*/

void ops_parse_and_accumulate(ops_keyring_t *keyring,ops_parse_options_t *opt)
    {
    accumulate_arg_t arg;

    assert(!opt->accumulate);

    memset(&arg,'\0',sizeof arg);

    arg.keyring=keyring;
    /* Kinda weird, but to do with counting, and we put it back after */
    --keyring->nkeys;
    arg.cb=opt->cb;
    arg.cb_arg=opt->cb_arg;

    opt->cb=accumulate_cb;
    opt->cb_arg=&arg;
    opt->accumulate=1;
    ops_parse(opt);
    ++keyring->nkeys;
    }

static void dump_one_key_data(const ops_key_data_t *key)
    {
    unsigned n;

    printf("Key ID: ");
    hexdump(key->keyid,8);

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
void ops_dump_keyring(const ops_keyring_t *keyring)
    {
    int n;

    for(n=0 ; n < keyring->nkeys ; ++n)
	dump_one_key_data(&keyring->keys[n]);
    }
