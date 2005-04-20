/* $Id$ */

#include "packet.h"
#include "packet-parse.h"
#include "util.h"
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static void showtime(const unsigned char *name,time_t t)
    {
    printf("%s=%ld (%.24s)",name,t,ctime(&t));
    }

static void bndump(const char *name,const BIGNUM *bn)
    {
    printf("    %s=",name);
    BN_print_fp(stdout,bn);
    putchar('\n');
    }

static ops_parse_callback_return_t
callback(const ops_parser_content_t *content_,void *arg_)
    {
    const ops_parser_content_union_t *content=&content_->content;
	int i=0; 	/* loop counter */
	
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

	case OPS_PKA_ELGAMAL:
	    bndump("p",content->public_key.key.elgamal.p);
	    bndump("g",content->public_key.key.elgamal.g);
	    bndump("y",content->public_key.key.elgamal.y);
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

    case OPS_PTAG_CT_COMPRESSED:
	printf("  compressed data type=%d\n",content->compressed.type);
	break;

    case OPS_PTAG_RAW_SS:
	assert(!content_->critical);
	printf("  raw signature subpacket tag=%d raw=",
	       content->ss_raw.tag-OPS_PTAG_SIGNATURE_SUBPACKET_BASE);
	hexdump(content->ss_raw.raw,content->ss_raw.length);
	putchar('\n');
	break;

    case OPS_PTAG_SS_CREATION_TIME:
	fputs("  creation time ",stdout);
	showtime("time",content->ss_time.time);
	putchar('\n');
	break;

    case OPS_PTAG_SS_ISSUER_KEY_ID:
	fputs("  issuer key id id=",stdout);
	hexdump(content->ss_issuer_key_id.key_id,
		sizeof content->ss_issuer_key_id.key_id);
	putchar('\n');
	break;

    case OPS_PTAG_SS_PREFERRED_SKA:
    printf("  preferred symmetric algorithms=");
    for (i=0; i<content->ss_preferred_ska.len; i++) {
    	switch (content->ss_preferred_ska.data[i]) {
    		case OPS_SKA_PLAINTEXT:
    			printf("Plaintext ");
    			break;
    		case OPS_SKA_IDEA:
    			printf("IDEA ");
    			break;
    		case OPS_SKA_TRIPLEDES:
    			printf("TripleDES ");
    			break;
    		case OPS_SKA_CAST5:
    			printf("CAST5 ");
    			break;
    		case OPS_SKA_BLOWFISH:
    			printf("Blowfish ");
    			break;
    		case OPS_SKA_AES_128:
    			printf("AES(128-bit) ");
    			break;
    		case OPS_SKA_AES_192:
    			printf("AES(192-bit) ");
    			break;
    		case OPS_SKA_AES_256:
    			printf("AES(256-bit) ");
    			break;
    		case OPS_SKA_TWOFISH:
    			printf("Twofish ");
    			break;
    		default:
    			printf("Unknown SKA: %d ",content->ss_preferred_ska.data[i]);
    	}
    }
	printf ("\n");
   	break;
    
    default:
	fprintf(stderr,"unknown tag=%d\n",content_->tag);
	exit(1);
	}
    return OPS_RELEASE_MEMORY;
    }

int main(int argc,char **argv)
    {
    ops_parse_options_t opt;
    ops_reader_fd_arg_t arg;

    ops_parse_options_init(&opt);
    //    ops_parse_packet_options(&opt,OPS_PTAG_SS_ALL,OPS_PARSE_RAW);
    ops_parse_options(&opt,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);
    opt.cb=callback;

    arg.fd=0;
    opt.reader_arg=&arg;
    opt.reader=ops_reader_fd;

    ops_parse(&opt);

    return 0;
    }
