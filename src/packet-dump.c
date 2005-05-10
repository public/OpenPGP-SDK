/* $Id$ */

#include "packet.h"
#include "packet-parse.h"
#include "packet-decode.h"
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

static void indent(int indent_level)
    {
    int i=0;
    for (i=0;i<indent_level;i++)
	printf("  ");
    }

static ops_parse_callback_return_t
callback(const ops_parser_content_t *content_,void *arg_)
    {
    const ops_parser_content_union_t *content=&content_->content;
    int i=0; 	/* loop counter */
    decoded_t * decoded;

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

    case OPS_PTAG_CT_TRUST:
	printf("Trust: "); 
	hexdump(content->trust.data,content->trust.len);
	printf("\n");
	break;
	
    case OPS_PTAG_CT_USER_ID:
	/* XXX: how do we print UTF-8? */
	printf("user id user_id=%s\n",content->user_id.user_id);
	break;

    case OPS_PTAG_CT_SIGNATURE:
	printf("signature version=%d type=0x%02x\n",
	       content->signature.version,content->signature.type);
	if (content->signature.version == 3) 
	    {
	    printf("          creation_time=%ld (%.24s)\n",
		   content->signature.creation_time,
		   ctime(&content->signature.creation_time));
	    }
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

    case OPS_PTAG_CT_ONE_PASS_SIGNATURE:
	printf("  one-pass signature version=%d sig_type=%d hash_algorith=%d"
	       " key_algorithm=%d\n",content->one_pass_signature.version,
	       content->one_pass_signature.sig_type,
	       content->one_pass_signature.hash_algorithm,
	       content->one_pass_signature.key_algorithm);
	printf("                     keyid=");
	hexdump(content->one_pass_signature.keyid,
		sizeof content->one_pass_signature.keyid);
	printf(" nested=%d\n",content->one_pass_signature.nested);
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

    case OPS_PTAG_SS_EXPIRATION_TIME:
	fputs("  expiration time ",stdout);
	printf ("%ld seconds after creation", content->ss_time.time);
	putchar('\n');
	break;

    case OPS_PTAG_SS_TRUST:
	printf ("  trust signature: level=%d, amount=%d\n",
		content->ss_trust.level,
		content->ss_trust.amount);
	break;
		
    case OPS_PTAG_SS_REVOCABLE:
	printf("  Revocable: ");
	if (content->ss_revocable.revocable)
	    {
	    printf("YES\n");
	    } 
	else 
	    {
	    printf("NO\n");
	    }
	break;      

    case OPS_PTAG_SS_REVOCATION_KEY:
	/* not yet tested */
	printf ("  revocation key: class=0x%x",
		content->ss_revocation_key.class);
	if (content->ss_revocation_key.class&0x40)
	    printf (" (sensitive)");
	printf (", algid=0x%x",
		content->ss_revocation_key.algid);
	printf(", fingerprint=");
	hexdump(content->ss_revocation_key.fingerprint,20);
	printf("\n");
	break;
    
    case OPS_PTAG_SS_ISSUER_KEY_ID:
	fputs("  issuer key id id=",stdout);
	hexdump(content->ss_issuer_key_id.key_id,
		sizeof content->ss_issuer_key_id.key_id);
	putchar('\n');
	break;

    case OPS_PTAG_SS_PREFERRED_SKA:

	printf("  Preferred Symmetric Algorithms: \n    ");

	decoded = decode_ss_preferred_ska(content->ss_preferred_ska);

	for ( i=0; i < decoded->known.used; i++) 
	    printf("%s ",decoded->known.strings[i]);

	for ( i=0; i < decoded->unknown.used; i++) 
	    printf("%s ",decoded->unknown.strings[i]);
	
	printf ("\n");
	decoded_free(decoded);

   	break;

    case OPS_PTAG_SS_PRIMARY_USER_ID:
	printf("  Primary User ID: ");
	if (content->ss_primary_user_id.primary_user_id)
	    {
	    printf("Yes\n");
	    } 
	else 
	    {
	    printf("No\n");
	    }
	break;      

    case OPS_PTAG_SS_PREFERRED_HASH:
	printf("  Preferred Hash Algorithms: \n    ");
	for (i=0; i<content->ss_preferred_hash.len; i++) 
	    {
	    switch (content->ss_preferred_hash.data[i]) 
		{
	    case OPS_HASH_MD5:
		printf("MD5");
		break;

	    case OPS_HASH_SHA1:
		printf("SHA1");
		break;

	    case OPS_HASH_RIPEMD:
		printf("RIPEMD160");
		break;

	    case OPS_HASH_SHA256:
		printf("SHA256");
		break;

	    case OPS_HASH_SHA384:
		printf("SHA384");
		break;

	    case OPS_HASH_SHA512:
		printf("SHA512");
		break;

	    default:
		if (content->ss_preferred_hash.data[i] >= 4 && 
		    content->ss_preferred_hash.data[i] <= 7)
		    printf("Reserved (%d)",
			   content->ss_preferred_hash.data[i]);
		else if (content->ss_preferred_hash.data[i] >= 100 && 
			 content->ss_preferred_hash.data[i] <= 110)
		    printf("Private/Experimental (%d)",
			   content->ss_preferred_hash.data[i]);	       
		else
		    printf("Unknown (%d)",content->ss_preferred_hash.data[i]);
		}
	    printf(" ");
	    }
	printf("\n");
	break;

    case OPS_PTAG_SS_PREFERRED_COMPRESSION:
	printf("  Preferred Compression Algorithms: \n    ");
	for (i=0; i<content->ss_preferred_compression.len; i++) 
	    {
	    switch (content->ss_preferred_compression.data[i]) 
		{
	    case OPS_C_NONE:
		printf("Uncompressed");
		break;

	    case OPS_C_ZIP:
		printf("ZIP(RFC1951)");
		break;

	    case OPS_C_ZLIB:
		printf("ZLIB(RFC1950)");
		break;

	    case OPS_C_BZIP2:
		printf("BZip2(BZ2)");
		break;

	    default:
		if (content->ss_preferred_compression.data[i] >= 100 && 
			 content->ss_preferred_compression.data[i] <= 110)
		    printf("Private/Experimental (%d)",
			   content->ss_preferred_compression.data[i]);	       
		else
		    printf("Unknown (%d)",content->ss_preferred_compression.data[i]);
		}
	    printf(" ");
	    }
	printf("\n");
	break;
	
    case OPS_PTAG_SS_KEY_FLAGS:
	printf("  Key Flags: len=%d, data=",content->ss_key_flags.len);
	hexdump(content->ss_key_flags.data,content->ss_key_flags.len);
	printf("\n");

	decoded = decode_ss_key_flags(content->ss_key_flags);
	for ( i=0; i < decoded->known.used; i++)
	    {
	    indent(2);
	    printf("%s\n",decoded->known.strings[i]);
	    }

	for ( i=0; i < decoded->unknown.used; i++) 
	    {
	    indent (2);
	    printf("%s\n",decoded->unknown.strings[i]);
	    }
	
	decoded_free(decoded);

	break;
	
    case OPS_PTAG_SS_KEY_SERVER_PREFS:
	printf("  Key Server Preferences: len=%d, data=",content->ss_key_server_prefs.len);
	hexdump(content->ss_key_server_prefs.data,content->ss_key_server_prefs.len);
	printf("\n");

	decoded = decode_ss_key_server_prefs(content->ss_key_server_prefs);
	for ( i=0; i < decoded->known.used; i++)
	    {
	    indent(2);
	    printf("%s\n",decoded->known.strings[i]);
	    }

	for ( i=0; i < decoded->unknown.used; i++) 
	    {
	    indent (2);
	    printf("%s\n",decoded->unknown.strings[i]);
	    }
	
	decoded_free(decoded);

	break;
	
    case OPS_PTAG_SS_FEATURES:
	printf("  Features: len=%d, data=",content->ss_features.len);
	hexdump(content->ss_features.data,content->ss_features.len);
	printf("\n");

	decoded = decode_ss_features(content->ss_features);
	for ( i=0; i < decoded->known.used; i++)
	    {
	    indent(2);
	    printf("%s\n",decoded->known.strings[i]);
	    }

	for ( i=0; i < decoded->unknown.used; i++) 
	    {
	    indent (2);
	    printf("%s\n",decoded->unknown.strings[i]);
	    }
	
	decoded_free(decoded);

	break;

    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
	printf("  literal data header format=%c filename='%s'\n",
	       content->literal_data_header.format,
	       content->literal_data_header.filename);
	showtime("    modification time",
		 content->literal_data_header.modification_time);
	printf("\n");
	break;

    case OPS_PTAG_CT_LITERAL_DATA_BODY:
	printf("  literal data body length=%d\n",
	       content->literal_data_body.length);
	printf("    data=");
	hexdump(content->literal_data_body.data,
		content->literal_data_body.length);
	printf("\n");
	break;

    default:
	fprintf(stderr,"packet-dump: unknown tag=%d\n",content_->tag);
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
