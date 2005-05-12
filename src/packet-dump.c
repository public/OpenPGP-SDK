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
    for(i=0 ; i<indent_level ; i++)
	printf("  ");
    }

static void print_time(char *label, time_t time, int indentlevel)
    {
    indent(indentlevel);
    printf("%s: ",label);
    showtime("time",time);
    printf("\n");
    }

static void print_duration(char *label, time_t time, int indentlevel)
    {
    int mins, hours, days, years;

    indent(indentlevel);
    printf("%s: ",label);
    printf("duration %ld seconds",time);

    mins=time/60;
    hours=mins/60;
    days=hours/24;
    years=days/365;

    printf(" (approx. ");
    if (years)
	printf("%d %s",years,years==1?"year":"years");
    else if (days)
	printf("%d %s",days,days==1?"day":"days");
    else if (hours)
	printf("%d %s", hours, hours==1?"hour":"hours");

    printf(")");
    printf("\n");
    }

static void print_decoded(char *label, decoded_t *decoded, int indentlevel)
    {
    int i=0;

    if(label)
	{
	indent(indentlevel);
	printf("%s:\n",label);
	}

    /* these were recognised */

    for(i=0 ; i<decoded->known.used ; i++) 
	{
	indent(indentlevel+1);
	printf("%s\n",decoded->known.strings[i]);
	}

    /* these were not recognised. the strings will contain the hex value
       of the unrecognised value in string format - see process_octet_str()
    */

    if(decoded->unknown.used)
	{
	printf("\n");
	indent(indentlevel+1);
	printf("Not Recognised: ");
	}
    for( i=0; i < decoded->unknown.used; i++) 
	{
	indent(indentlevel+2);
	printf("%s\n",decoded->unknown.strings[i]);
	}
	
    }

static void print_hexdump(char *label,const unsigned char *data,
			  unsigned int len, int indentlevel)
    {
    if(label)
	{
	indent(indentlevel);
	printf("%s: len=%d, data=0x", label, len);
	}

    hexdump(data,len);
    printf("\n");
    }

static void print_boolean(char *label, unsigned char bool, int indentlevel)
    {
    if(label)
	{
	indent(indentlevel);
	printf("%s: ", label);
	}
    if(bool)
	printf("Yes");
    else
	printf("No");
    printf("\n");
    }

static void print_string(char *label, char *str, int indentlevel)
    {
    if(label)
	{
	indent(indentlevel);
	printf("%s:\n", label);
	}

    indent(indentlevel+1);
    printf("%s\n", str);
    }

static ops_parse_callback_return_t
callback(const ops_parser_content_t *content_,void *arg_)
    {
    const ops_parser_content_union_t *content=&content_->content;
    decoded_t * decoded;
    char *str;

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

    case OPS_PTAG_CT_USER_ATTRIBUTE:
	print_hexdump("User Attribute",
		      content->user_attribute.data.contents,
		      content->user_attribute.data.len,
		      1);
	break;

    case OPS_PTAG_RAW_SS:
	assert(!content_->critical);
	printf("  raw signature subpacket tag=%d raw=",
	       content->ss_raw.tag-OPS_PTAG_SIGNATURE_SUBPACKET_BASE);
	hexdump(content->ss_raw.raw,content->ss_raw.length);
	putchar('\n');
	break;

    case OPS_PTAG_SS_CREATION_TIME:
	print_time("Signature Creation Time",content->ss_time.time,1);
	break;

    case OPS_PTAG_SS_EXPIRATION_TIME:
	print_duration("Signature Expiration Time",content->ss_time.time,1);
	break;

    case OPS_PTAG_SS_KEY_EXPIRATION_TIME:
	print_duration("Key Expiration Time", content->ss_time.time, 1);
	break;

    case OPS_PTAG_SS_TRUST:
	printf ("  trust signature: level=%d, amount=%d\n",
		content->ss_trust.level,
		content->ss_trust.amount);
	break;
		
    case OPS_PTAG_SS_REVOCABLE:
	print_boolean("Revocable",content->ss_revocable.revocable,1);
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
	print_hexdump("Issuer Key Id",
		      &content->ss_issuer_key_id.key_id[0],
		      sizeof content->ss_issuer_key_id.key_id,
		      1);
	break;

    case OPS_PTAG_SS_PREFERRED_SKA:
	decoded = decode_ss_preferred_ska(content->ss_preferred_ska);
	print_decoded("Preferred Symmetric Algorithms",decoded,1);
	decoded_free(decoded);

   	break;

    case OPS_PTAG_SS_PRIMARY_USER_ID:
	print_boolean("Primary User ID",
		      content->ss_primary_user_id.primary_user_id,
		      1);
	break;      

    case OPS_PTAG_SS_PREFERRED_HASH:
	decoded = decode_ss_preferred_hash(content->ss_preferred_hash);
	print_decoded("Preferred Hash Algorithms",decoded,1);
	decoded_free(decoded);
	break;

    case OPS_PTAG_SS_PREFERRED_COMPRESSION:
	decoded = decode_ss_preferred_compression(content->ss_preferred_compression);
	print_decoded("Preferred Compression Algorithms",decoded,1);
	decoded_free(decoded);
	break;
	
    case OPS_PTAG_SS_KEY_FLAGS:
	print_hexdump("Key Flags", 
		      content->ss_key_flags.data,
		      content->ss_key_flags.len,
		      1);

	decoded = decode_ss_key_flags(content->ss_key_flags);
	print_decoded(NULL, decoded, 1);
	decoded_free(decoded);

	break;
	
    case OPS_PTAG_SS_KEY_SERVER_PREFS:
	print_hexdump("Key Server Preferences",
		      content->ss_key_server_prefs.data,
		      content->ss_key_server_prefs.len,
		      1);

	decoded = decode_ss_key_server_prefs(content->ss_key_server_prefs);
	print_decoded(NULL, decoded, 1);
	decoded_free(decoded);

	break;
	
    case OPS_PTAG_SS_FEATURES:
	print_hexdump("Features", 
		      content->ss_features.data,
		      content->ss_features.len,
		      1);

	decoded = decode_ss_features(content->ss_features);
	print_decoded(NULL,decoded,1);
	decoded_free(decoded);

	break;

    case OPS_PTAG_SS_USERDEFINED00:
    case OPS_PTAG_SS_USERDEFINED01:
    case OPS_PTAG_SS_USERDEFINED02:
    case OPS_PTAG_SS_USERDEFINED03:
    case OPS_PTAG_SS_USERDEFINED04:
    case OPS_PTAG_SS_USERDEFINED05:
    case OPS_PTAG_SS_USERDEFINED06:
    case OPS_PTAG_SS_USERDEFINED07:
    case OPS_PTAG_SS_USERDEFINED08:
    case OPS_PTAG_SS_USERDEFINED09:
    case OPS_PTAG_SS_USERDEFINED10:
	print_hexdump("Internal or user-defined",
		      content->ss_userdefined.data.contents,
		      content->ss_userdefined.data.len,
		      1);
	break;

    case OPS_PTAG_SS_REVOCATION_REASON:
	print_hexdump("Revocation Reason",
		      &content->ss_revocation_reason.code,
		      1,
		      1);
	str = decode_ss_revocation_reason_code(content->ss_revocation_reason.code);
	print_string(NULL,str,1);
	/* xxx - todo : output text as UTF-8 string */
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
