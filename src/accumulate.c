#include "packet.h"
#include "packet-parse.h"
#include "util.h"
#include <assert.h>
#include <stdlib.h>

typedef struct
    {
    unsigned nuids;
    unsigned nuids_allocated;
    ops_user_id_t *uids;
    unsigned npackets;
    unsigned npackets_allocated;
    ops_packet_t *packets;
    } key_data_t;

typedef struct
    {
    ops_packet_parse_callback_t *cb;
    void *cb_arg;
    int nkeys; // while we are constructing a key, this is the offset
    int nkeys_allocated;
    key_data_t *keys;
    } accumulate_arg_t;    

static void accumulate_cb(const ops_parser_content_t *content_,void *arg_)
    {
    accumulate_arg_t *arg=arg_;
    const ops_parser_content_union_t *content=&content_->content;
    key_data_t *cur=&arg->keys[arg->nkeys];

    switch(content_->tag)
	{
    case OPS_PTAG_CT_PUBLIC_KEY:
	//	printf("New key\n");
	++arg->nkeys;
	if(arg->nkeys == arg->nkeys_allocated)
	    {
	    arg->nkeys_allocated=arg->nkeys_allocated*2+10;
	    arg->keys=realloc(arg->keys,
			      arg->nkeys_allocated*sizeof *arg->keys);
	    }
	memset(&arg->keys[arg->nkeys],'\0',sizeof arg->keys[arg->nkeys]);
	break;

    case OPS_PTAG_CT_USER_ID:
	//	printf("User ID: %s\n",content->user_id.user_id);
	if(cur->nuids == cur->nuids_allocated)
	    {
	    cur->nuids_allocated=cur->nuids_allocated*2+10;
	    cur->uids=realloc(cur->uids,
			      cur->nuids_allocated*sizeof *cur->uids);
	    }
	cur->uids[cur->nuids++]=content->user_id;
	break;

    case OPS_PARSER_PACKET_END:
	if(cur->npackets_allocated == cur->npackets)
	    {
	    cur->npackets_allocated=cur->npackets_allocated*2+10;
	    cur->packets=realloc(cur->packets,cur->npackets_allocated
				 *sizeof *cur->packets);
	    }
	cur->packets[cur->npackets++]=content->packet;
	break;

    case OPS_PARSER_ERROR:
	fprintf(stderr,"Error: %s\n",content->error.error);
	break;

    default:
	break;
	}

    if(arg->cb)
	arg->cb(content_,arg->cb_arg);
    }

static void dump_one_key_data(const key_data_t *key)
    {
    int n;

    printf("UIDs\n====\n\n");
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

static void dump_key_data(const key_data_t *keys,int nkeys)
    {
    int n;

    for(n=0 ; n < nkeys ; ++n)
	dump_one_key_data(&keys[n]);
    }

void ops_parse_and_accumulate(ops_parse_options_t *opt)
    {
    accumulate_arg_t arg;

    assert(!opt->accumulate);

    memset(&arg,'\0',sizeof arg);

    arg.nkeys=-1;
    arg.cb=opt->cb;
    arg.cb_arg=opt->cb_arg;

    opt->cb=accumulate_cb;
    opt->cb_arg=&arg;
    opt->accumulate=1;
    ops_parse(opt);
    ++arg.nkeys;

    dump_key_data(arg.keys,arg.nkeys);
    }
