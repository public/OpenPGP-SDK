#include "packet.h"
#include "packet-parse.h"
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

static void hexdump(const unsigned char *src,size_t length)
    {
    while(length--)
	printf("%02X",*src++);
    }

static ops_packet_reader_ret_t reader(unsigned char *dest,unsigned length)
    {
    int n=read(0,dest,length);

    if(n == 0)
	return OPS_PR_EOF;

    if(n != length)
	return OPS_PR_EARLY_EOF;
#if 0
    printf("[read 0x%x: ",length);
    hexdump(dest,length);
    putchar(']');
#endif
    return OPS_PR_OK;
    }

static void bndump(const char *name,const BIGNUM *bn)
    {
    printf("    %s=",name);
    BN_print_fp(stdout,bn);
    putchar('\n');
    }

static void callback(const ops_parser_content_t *content_)
    {
    const ops_parser_content_union_t *content=&content_->content;

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
    case OPS_PTAG_CT_PUBLIC_SUBKEY:
	printf("public %skey version=%d creation_time=%ld (%.24s)\n",
	       content_->tag == OPS_PTAG_CT_PUBLIC_KEY ? "" : "sub",
	       content->public_key.version,content->public_key.creation_time,
	       ctime(&content->public_key.creation_time));
	/* XXX: convert algorithm to string */
	printf("           %sdays_valid=%d algorithm=%d\n",
	       content_->tag == OPS_PTAG_CT_PUBLIC_KEY ? "" : "   ",
	       content->public_key.days_valid,content->public_key.algorithm);
	switch(content->public_key.algorithm)
	    {
	case OPS_PKA_DSA:
	    bndump("p",content->public_key.key.dsa.p);
	    bndump("q",content->public_key.key.dsa.q);
	    bndump("g",content->public_key.key.dsa.g);
	    bndump("y",content->public_key.key.dsa.y);
	    break;

	case OPS_PKA_RSA:
	case OPS_PKA_RSA_ENCRYPT_ONLY:
	case OPS_PKA_RSA_SIGN_ONLY:
	    bndump("n",content->public_key.key.rsa.n);
	    bndump("e",content->public_key.key.rsa.e);
	    break;

	case OPS_PKA_ELGAMEL:
	    bndump("p",content->public_key.key.elgamel.p);
	    bndump("g",content->public_key.key.elgamel.g);
	    bndump("y",content->public_key.key.elgamel.y);
	    break;

	default:
	    assert(0);
	    }
	break;

    case OPS_PTAG_CT_USER_ID:
	/* XXX: how do we print UTF-8? */
	printf("user id user_id=%s\n",content->user_id.user_id);
	break;

    case OPS_PTAG_CT_SIGNATURE:
	printf("signature version=%d type=0x%02x\n",
	       content->signature.version,content->signature.type);
	printf("          creation_time=%ld (%.24s)\n",
	       content->signature.creation_time,
	       ctime(&content->signature.creation_time));
	printf("          signer_id=");
	hexdump(content->signature.signer_id,
		sizeof content->signature.signer_id);
	printf(" key_algorithm=%d hash_algorithm=%d\n",
	       content->signature.key_algorithm,
	       content->signature.hash_algorithm);
	printf("          hash2=%02x%02x\n",content->signature.hash2[0],
	       content->signature.hash2[1]);
	switch(content->signature.key_algorithm)
	    {
	case OPS_PKA_RSA:
	    bndump("sig",content->signature.signature.rsa.sig);
	    break;

	case OPS_PKA_DSA:
	    bndump("r",content->signature.signature.dsa.r);
	    bndump("s",content->signature.signature.dsa.s);
	    break;

	default:
	    assert(0);
	    }    
	break;

    case OPS_PTAG_RAW_SS:
	assert(!content_->critical);
	printf("raw signature subpacket tag=%d raw=",
	       content->ss_raw.tag-OPS_PTAG_SIGNATURE_SUBPACKET_BASE);
	hexdump(content->ss_raw.raw,content->ss_raw.length);
	putchar('\n');
	break;

    default:
	fprintf(stderr,"unknown tag=%d\n",content_->tag);
	exit(1);
	}
    }

int main(int argc,char **argv)
    {
    ops_parse_packet_options_t opt;

    ops_parse_packet_options_init(&opt);
    ops_parse_packet_options(&opt,OPS_PTAG_SS_ALL,OPS_PARSE_RAW);
    ops_parse_packet(reader,callback,&opt);

    return 0;
    }
