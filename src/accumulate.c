#include "packet.h"
#include "packet-parse.h"
#include "util.h"
#include "accumulate.h"
#include <assert.h>
#include <stdlib.h>

#define DECLARE_ARRAY(type,arr)	unsigned n##arr; unsigned n##arr##_allocated; type *arr
#define EXPAND_ARRAY(str,arr) do if(str->n##arr == str->n##arr##_allocated) \
				{ \
				str->n##arr##_allocated=str->n##arr##_allocated*2+10; \
				str->arr=realloc(str->arr,str->n##arr##_allocated*sizeof *str->arr); \
				} while(0)

typedef struct
    {
    ops_packet_parse_callback_t *cb;
    void *cb_arg;
    ops_keyring_t *keyring;
    } accumulate_arg_t;

struct ops_key_data
    {
    DECLARE_ARRAY(ops_user_id_t,uids);
    DECLARE_ARRAY(ops_packet_t,packets);
    unsigned char keyid[8];
    ops_fingerprint_t fingerprint;
    };

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
	break;

    case OPS_PTAG_CT_USER_ID:
	//	printf("User ID: %s\n",content->user_id.user_id);
	EXPAND_ARRAY(cur,uids);
	cur->uids[cur->nuids++]=content->user_id;
	break;

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

    if(arg->cb)
	return arg->cb(content_,arg->cb_arg);
    return OPS_RELEASE_MEMORY;
    }

static void dump_one_key_data(const ops_key_data_t *key)
    {
    int n;

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

static void dump_key_data(const ops_keyring_t *keyring)
    {
    int n;

    for(n=0 ; n < keyring->nkeys ; ++n)
	dump_one_key_data(&keyring->keys[n]);
    }

static void validate_key_signatures(const ops_key_data_t *key,
				    const ops_keyring_t *ring)
    {
    }

static void validate_all_signatures(const ops_keyring_t *ring)
    {
    int n;

    for(n=0 ; n < ring->nkeys ; ++n)
	validate_key_signatures(&ring->keys[n],ring);
    }

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

    dump_key_data(keyring);
    validate_all_signatures(keyring);
    }
