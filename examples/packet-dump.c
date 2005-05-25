#include "packet.h"
#include "packet-parse.h"
#include "packet-to-text.h"
#include "util.h"
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static int indent=0;

static void print_indent()
    {
    int i=0;
    for(i=0 ; i<indent ; i++)
	printf("  ");
    }

static void showtime(const unsigned char *name,time_t t)
    {
    printf("%s=%ld (%.24s)",name,t,ctime(&t));
    }

static void print_bn( const char *name, const BIGNUM *bn)
    {
    print_indent();
    printf("%s=",name);
    BN_print_fp(stdout,bn);
    printf("\n");
    }

static void print_time( char *name, time_t time)
    {
    print_indent();
    printf("%s: ",name);
    showtime("time",time);
    printf("\n");
    }

static void print_duration(char *name, time_t time)
    {
    int mins, hours, days, years;

    print_indent();
    printf("%s: ",name);
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

static void print_name( char *name)
    {
    print_indent();
    if(name)
	printf("%s: ",name);
    }

static void print_text_breakdown( text_t *text)
    {
    int i=0;
    char *prefix=".. ";

    /* these were recognised */

    for(i=0 ; i<text->known.used ; i++) 
	{
	print_indent();
	printf(prefix);
	printf("%s\n",text->known.strings[i]);
	}

    /* these were not recognised. the strings will contain the hex value
       of the unrecognised value in string format - see process_octet_str()
    */

    if(text->unknown.used)
	{
	printf("\n");
	print_indent();
	printf("Not Recognised: ");
	}
    for( i=0; i < text->unknown.used; i++) 
	{
	print_indent();
	printf(prefix);
	printf("%s\n",text->unknown.strings[i]);
	}
	
    }

static void print_hexdump( char *name,
			  const unsigned char *data,
			  unsigned int len)
    {
    print_name(name);

    printf("len=%d, data=0x", len);
    hexdump(data,len);
    printf("\n");
    }

static void print_hexdump_data( char *name,
			  const unsigned char *data,
			  unsigned int len)
    {
    print_name(name);

    printf("0x");
    hexdump(data,len);
    printf("\n");
    }

static void print_data( char *name, const ops_data_t *data)
    {
    print_hexdump( name, data->contents, data->len);
    }


static void print_boolean(char *name, unsigned char bool)
    {
    print_name(name);

    if(bool)
	printf("Yes");
    else
	printf("No");
    printf("\n");
    }

static void print_tagname( char *str)
    {
    print_indent();
    printf("%s packet\n", str);
    }

static void print_string(char *name, char *str)
    {
    print_name(name);
    while(*str)
	{
	if(*str >= 0x20 && *str < 0x7f && *str != '%')
	    putchar(*str);
	else
	    printf("%%%02x",(unsigned char)*str);
	++str;
	}
    }

static void print_unsigned_int( char *name, unsigned int val)
    {
    print_name(name);
    printf("%d\n", val);
    }

static void print_string_and_value( char *name, char *str, unsigned char value)
    {

    print_name(name);

    printf("%s", str);
    printf(" (0x%x)", value);
    printf("\n");
    }

static void start_subpacket(unsigned type)
    {
    indent++;
    print_indent();
    printf("-- %s (type 0x%x)\n",
	   str_from_single_signature_subpacket_type(type),
	   type);
    }
 
static void end_subpacket()
    {
    indent--;
    }

static ops_parse_callback_return_t
callback(const ops_parser_content_t *content_,void *arg_)
    {
    const ops_parser_content_union_t *content=&content_->content;
    text_t * text;
    char *str;

    switch(content_->tag)
	{
    case OPS_PARSER_ERROR:
	printf("parse error: %s\n",content->error.error);
	break;

    case OPS_PARSER_PTAG:

	if (content->ptag.content_tag==OPS_PTAG_CT_PUBLIC_KEY)
	    {
	    indent=0;
	    printf("\n*** NEXT KEY ***\n");
	    }

	printf("\n");
	print_indent();
	printf("==== ptag new_format=%d content_tag=%d length_type=%d"
	       " length=0x%x (%d)\n",content->ptag.new_format,
	       content->ptag.content_tag,content->ptag.length_type,
	       content->ptag.length,content->ptag.length);
	/*
	print_tagname(str_from_single_packet_tag(content->ptag.content_tag));
	*/
	break;

    case OPS_PTAG_CT_PUBLIC_KEY:
    case OPS_PTAG_CT_PUBLIC_SUBKEY:

	if (content_->tag == OPS_PTAG_CT_PUBLIC_KEY)
	    print_tagname("PUBLIC KEY");
	else
	    print_tagname("PUBLIC SUBKEY");

	print_unsigned_int("Version",content->public_key.version);
	print_time("Creation Time", content->public_key.creation_time);
	print_unsigned_int("Days Valid",content->public_key.days_valid);

	str=str_from_single_pka(content->public_key.algorithm);
	print_string_and_value("Algorithm",str,content->public_key.algorithm);

	switch(content->public_key.algorithm)
	    {
	case OPS_PKA_DSA:
	    print_bn("p",content->public_key.key.dsa.p);
	    print_bn("q",content->public_key.key.dsa.q);
	    print_bn("g",content->public_key.key.dsa.g);
	    print_bn("y",content->public_key.key.dsa.y);
	    break;

	case OPS_PKA_RSA:
	case OPS_PKA_RSA_ENCRYPT_ONLY:
	case OPS_PKA_RSA_SIGN_ONLY:
	    print_bn("n",content->public_key.key.rsa.n);
	    print_bn("e",content->public_key.key.rsa.e);
	    break;

	case OPS_PKA_ELGAMAL:
	    print_bn("p",content->public_key.key.elgamal.p);
	    print_bn("g",content->public_key.key.elgamal.g);
	    print_bn("y",content->public_key.key.elgamal.y);
	    break;

	default:
	    assert(0);
	    }
	break;

    case OPS_PTAG_CT_TRUST:
	print_tagname("TRUST");
	print_data("Trust",&content->trust.data);
	break;
	
    case OPS_PTAG_CT_USER_ID:
	/* XXX: how do we print UTF-8? */
	print_tagname("USER ID");
	print_string("user_id",content->user_id.user_id);
	break;

    case OPS_PTAG_CT_SIGNATURE:
	print_tagname("SIGNATURE");
	print_indent(indent);
	print_unsigned_int("Signature Version",
	       content->signature.version);
	if (content->signature.version == 3) 
	    print_time("Signature Creation Time", content->signature.creation_time);

	print_string_and_value("Signature Type",
			       str_from_single_signature_type(content->signature.type),
			       content->signature.type);

	print_hexdump_data("Signer ID",
		      content->signature.signer_id,
		      sizeof content->signature.signer_id);

	print_string_and_value("Public Key Algorithm",
			       str_from_single_pka(content->signature.key_algorithm),
			       content->signature.key_algorithm);
	print_string_and_value("Hash Algorithm",
			       str_from_single_hash_algorithm(content->signature.hash_algorithm),
			       content->signature.hash_algorithm);

	print_indent();
	print_hexdump_data("hash2",&content->signature.hash2[0],2);

	switch(content->signature.key_algorithm)
	    {
	case OPS_PKA_RSA:
	    print_bn("sig",content->signature.signature.rsa.sig);
	    break;

	case OPS_PKA_DSA:
	    print_bn("r",content->signature.signature.dsa.r);
	    print_bn("s",content->signature.signature.dsa.s);
	    break;

	case OPS_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
	    print_bn("r",content->signature.signature.elgamal.r);
	    print_bn("s",content->signature.signature.elgamal.s);
	    break;

	default:
	    assert(0);
	    }    
	break;

    case OPS_PTAG_CT_COMPRESSED:
	print_tagname("COMPRESSED");
	print_unsigned_int("Compressed Data Type", content->compressed.type);
	break;

    case OPS_PTAG_CT_ONE_PASS_SIGNATURE:
	print_tagname("ONE PASS SIGNATURE");

	print_unsigned_int("Version",content->one_pass_signature.version);
	print_string_and_value("Signature Type",
			       str_from_single_signature_type(content->one_pass_signature.sig_type),
			       content->one_pass_signature.sig_type);
	print_string_and_value("Hash Algorithm",
			       str_from_single_hash_algorithm(content->one_pass_signature.hash_algorithm),
			       content->one_pass_signature.hash_algorithm);
	print_string_and_value("Public Key Algorithm",
			       str_from_single_pka(content->one_pass_signature.key_algorithm),
			       content->one_pass_signature.key_algorithm);
 	print_hexdump("Signer ID",
		      content->one_pass_signature.keyid,
		      sizeof content->one_pass_signature.keyid);

	print_unsigned_int("Nested",
			   content->one_pass_signature.nested);
	break;

    case OPS_PTAG_CT_USER_ATTRIBUTE:
	print_tagname("USER ATTRIBUTE");
	print_hexdump("User Attribute",
		      content->user_attribute.data.contents,
		      content->user_attribute.data.len);
	break;

    case OPS_PTAG_RAW_SS:
	assert(!content_->critical);
	start_subpacket(content_->tag);
	print_unsigned_int("Raw Signature Subpacket: tag",
			   content->ss_raw.tag-OPS_PTAG_SIGNATURE_SUBPACKET_BASE);
	print_hexdump("Raw Data",
		      content->ss_raw.raw,
		      content->ss_raw.length);
	break;

    case OPS_PTAG_SS_CREATION_TIME:
	start_subpacket(content_->tag);
	print_time("Signature Creation Time",content->ss_time.time);
	end_subpacket();
	break;

    case OPS_PTAG_SS_EXPIRATION_TIME:
	start_subpacket(content_->tag);
	print_duration("Signature Expiration Time",content->ss_time.time);
	end_subpacket();
	break;

    case OPS_PTAG_SS_KEY_EXPIRATION_TIME:
	start_subpacket(content_->tag);
	print_duration("Key Expiration Time", content->ss_time.time);
	end_subpacket();
	break;

    case OPS_PTAG_SS_TRUST:
	start_subpacket(content_->tag);
	print_string("Trust Signature","");
	print_unsigned_int("Level",
			   content->ss_trust.level);
	print_unsigned_int("Amount",
			   content->ss_trust.amount);
	end_subpacket();
	break;
		
    case OPS_PTAG_SS_REVOCABLE:
	start_subpacket(content_->tag);
	print_boolean("Revocable",content->ss_revocable.revocable);
	end_subpacket();
	break;      

    case OPS_PTAG_SS_REVOCATION_KEY:
	start_subpacket(content_->tag);
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
	end_subpacket();
	break;
    
    case OPS_PTAG_SS_ISSUER_KEY_ID:
	start_subpacket(content_->tag);
	print_hexdump("Issuer Key Id",
		      &content->ss_issuer_key_id.key_id[0],
		      sizeof content->ss_issuer_key_id.key_id);
	end_subpacket();
	break;

    case OPS_PTAG_SS_PREFERRED_SKA:
	start_subpacket(content_->tag);
	print_data( "Preferred Symmetric Algorithms",
		   &content->ss_preferred_ska.data);

	text = text_from_ss_preferred_ska(content->ss_preferred_ska);
	print_text_breakdown(text);
	text_free(text);

	end_subpacket();
   	break;

    case OPS_PTAG_SS_PRIMARY_USER_ID:
	start_subpacket(content_->tag);
	print_boolean("Primary User ID",
		      content->ss_primary_user_id.primary_user_id);
	end_subpacket();
	break;      

    case OPS_PTAG_SS_PREFERRED_HASH:
	start_subpacket(content_->tag);
	print_data( "Preferred Hash Algorithms",
		   &content->ss_preferred_hash.data);

	text = text_from_ss_preferred_hash(content->ss_preferred_hash);
	print_text_breakdown(text);
	text_free(text);
	end_subpacket();
	break;

    case OPS_PTAG_SS_PREFERRED_COMPRESSION:
	start_subpacket(content_->tag);
	print_data( "Preferred Compression Algorithms",
		   &content->ss_preferred_compression.data);

	text = text_from_ss_preferred_compression(content->ss_preferred_compression);
	print_text_breakdown(text);
	text_free(text);
	end_subpacket();
	break;
	
    case OPS_PTAG_SS_KEY_FLAGS:
	start_subpacket(content_->tag);
	print_data( "Key Flags", &content->ss_key_flags.data);

	text = text_from_ss_key_flags(content->ss_key_flags);
	print_text_breakdown( text);
	text_free(text);

	end_subpacket();
	break;
	
    case OPS_PTAG_SS_KEY_SERVER_PREFS:
	start_subpacket(content_->tag);
	print_data( "Key Server Preferences",
		   &content->ss_key_server_prefs.data);

	text = text_from_ss_key_server_prefs(content->ss_key_server_prefs);
	print_text_breakdown( text);
	text_free(text);

	end_subpacket();
	break;
	
    case OPS_PTAG_SS_FEATURES:
	start_subpacket(content_->tag);
	print_data( "Features", 
		   &content->ss_features.data);

	text = text_from_ss_features(content->ss_features);
	print_text_breakdown( text);
	text_free(text);

	end_subpacket();
	break;

    case OPS_PTAG_SS_NOTATION_DATA:
	start_subpacket(content_->tag);
	print_indent();
	printf("Notation Data:\n");

	indent++;
	print_data( "Flags",
		   &content->ss_notation_data.flags);
	text = text_from_ss_notation_data_flags(content->ss_notation_data);
	print_text_breakdown( text);
	text_free(text);

	/* xxx - TODO: print out UTF - rachel */

	print_data( "Name",
		   &content->ss_notation_data.name);

	print_data( "Value",
		   &content->ss_notation_data.value);

	indent--;
	end_subpacket();
	break;

    case OPS_PTAG_SS_REGEXP:
	start_subpacket(content_->tag);
	print_hexdump("Regular Expression",
		      content->ss_regexp.text,
		      strlen(content->ss_regexp.text));
	print_string(NULL,
		     content->ss_regexp.text);
	end_subpacket();
	break;

    case OPS_PTAG_SS_POLICY_URL:
	start_subpacket(content_->tag);
	print_string("Policy URL",
		     content->ss_policy_url.text);
	end_subpacket();
	break;

    case OPS_PTAG_SS_PREFERRED_KEY_SERVER:
	start_subpacket(content_->tag);
	print_string("Preferred Key Server",
		     content->ss_preferred_key_server.text);
	end_subpacket();
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
	start_subpacket(content_->tag);
	print_hexdump("Internal or user-defined",
		      content->ss_userdefined.data.contents,
		      content->ss_userdefined.data.len);
	end_subpacket();
	break;

    case OPS_PTAG_SS_REVOCATION_REASON:
	start_subpacket(content_->tag);
	print_hexdump("Revocation Reason",
		      &content->ss_revocation_reason.code,
		      1);
	str = str_from_ss_revocation_reason_code(content->ss_revocation_reason.code);
	print_string(NULL,str);
	/* xxx - todo : output text as UTF-8 string */
	end_subpacket();
	break;

    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
	print_tagname("LITERAL DATA HEADER");
	printf("  literal data header format=%c filename='%s'\n",
	       content->literal_data_header.format,
	       content->literal_data_header.filename);
	showtime("    modification time",
		 content->literal_data_header.modification_time);
	printf("\n");
	break;

    case OPS_PTAG_CT_LITERAL_DATA_BODY:
	print_tagname("LITERAL DATA BODY");
	printf("  literal data body length=%d\n",
	       content->literal_data_body.length);
	printf("    data=");
	hexdump(content->literal_data_body.data,
		content->literal_data_body.length);
	printf("\n");
	break;

    case OPS_PTAG_CT_SIGNATURE_HEADER:
	print_tagname("SIGNATURE");
	print_indent(indent);
	print_unsigned_int("Signature Version",
	       content->signature.version);
	if (content->signature.version == 3) 
	    print_time("Signature Creation Time", content->signature.creation_time);

	print_string_and_value("Signature Type",
			       str_from_single_signature_type(content->signature.type),
			       content->signature.type);

	print_hexdump_data("Signer ID",
		      content->signature.signer_id,
		      sizeof content->signature.signer_id);

	print_string_and_value("Public Key Algorithm",
			       str_from_single_pka(content->signature.key_algorithm),
			       content->signature.key_algorithm);
	print_string_and_value("Hash Algorithm",
			       str_from_single_hash_algorithm(content->signature.hash_algorithm),
			       content->signature.hash_algorithm);

	break;

    case OPS_PTAG_CT_SIGNATURE_FOOTER:
	print_indent();
	print_hexdump_data("hash2",&content->signature.hash2[0],2);

	switch(content->signature.key_algorithm)
	    {
	case OPS_PKA_RSA:
	    print_bn("sig",content->signature.signature.rsa.sig);
	    break;

	case OPS_PKA_DSA:
	    print_bn("r",content->signature.signature.dsa.r);
	    print_bn("s",content->signature.signature.dsa.s);
	    break;

	case OPS_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
	    print_bn("r",content->signature.signature.elgamal.r);
	    print_bn("s",content->signature.signature.elgamal.s);
	    break;

	default:
	    assert(0);
	    }
	break;

    case OPS_PTAG_CT_SECRET_KEY:
	// XXX: fix me
	printf("***RACHEL DO YOUR THING HERE***\n");
	break;

    default:
	print_tagname("UNKNOWN PACKET TYPE");
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
