#include "packet.h"
#include "packet-parse.h"
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

static ops_packet_reader_ret_t reader(unsigned char *dest,unsigned length)
    {
    int n=read(0,dest,length);

    if(n == 0)
	return OPS_PR_EOF;

    if(n != length)
	return OPS_PR_EARLY_EOF;

    return OPS_PR_OK;
    }

void callback(ops_parser_content_t *content_)
    {
    ops_parser_content_union_t *content=&content_->content;

    switch(content_->tag)
	{
    case OPS_PARSER_ERROR:
	printf("parse error: %s\n",content->error.error);
	break;

    case OPS_PARSER_PTAG:
	printf("ptag new_format=%d content_tag=%d length_type=%d"
	       " length=0x%x (%d)\n",content->ptag.new_format,
	       content->ptag.content_tag,content->ptag.length_type,
	       content->ptag.length,content->ptag.length);
	break;

    case OPS_PTAG_CT_PUBLIC_KEY:
	printf("public key version=%d creation_time=%ld (%.24s)\n",
	       content->public_key.version,content->public_key.creation_time,
	       ctime(&content->public_key.creation_time));
	/* XXX: convert algorithm to string */
	printf("           days_valid=%d algorithm=%d\n",
	       content->public_key.days_valid,content->public_key.algorithm);
	switch(content->public_key.algorithm)
	    {
	case OPS_PKA_DSA:
	    printf("  p=");
	    BN_print_fp(stdout,content->public_key.key.dsa.p);
	    printf("\n  q=");
	    BN_print_fp(stdout,content->public_key.key.dsa.q);
	    printf("\n  g=");
	    BN_print_fp(stdout,content->public_key.key.dsa.g);
	    printf("\n  y=");
	    BN_print_fp(stdout,content->public_key.key.dsa.y);
	    break;
	case OPS_PKA_RSA:
	case OPS_PKA_RSA_ENCRYPT_ONLY:
	case OPS_PKA_RSA_SIGN_ONLY:
	    printf("  n=");
	    BN_print_fp(stdout,content->public_key.key.rsa.n);
	    printf("\n  e=");
	    BN_print_fp(stdout,content->public_key.key.rsa.e);
	    break;
	    
	default:
	    assert(0);
	    }
	putchar('\n');
	break;

    case OPS_PTAG_CT_USER_ID:
	/* XXX: how do we print UTF-8? */
	printf("user id user_id=%s\n",content->user_id.user_id);
	break;

    default:
	fprintf(stderr,"unknown tag=%d\n",content_->tag);
	exit(1);
	}
    }

int main(int argc,char **argv)
    {
    ops_parse_packet(reader,callback);

    return 0;
    }
