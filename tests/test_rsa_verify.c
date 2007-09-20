#include "CUnit/Basic.h"

#include <openpgpsdk/types.h>
#include "openpgpsdk/keyring.h"
#include <openpgpsdk/armour.h>
#include "openpgpsdk/packet.h"
#include "openpgpsdk/packet-parse.h"
#include "openpgpsdk/util.h"
#include "openpgpsdk/std_print.h"
#include "openpgpsdk/readerwriter.h"
#include "openpgpsdk/validate.h"

#include "tests.h"

typedef struct
    {
    const ops_key_data_t *key;
    unsigned packet;
    unsigned offset;
    } validate_reader_arg_t;

typedef struct
    {
    ops_public_key_t pkey;
    ops_public_key_t subkey;
    enum
	{
	ATTRIBUTE,
	ID
	} last_seen;
    ops_user_id_t user_id;
    ops_user_attribute_t user_attribute;
    const ops_keyring_t *keyring;
    validate_reader_arg_t *rarg;
    ops_validate_result_t *result;
    } validate_cb_arg_t;

static char *filename_rsa_noarmour_nopassphrase="gpg_signed_noarmour_nopassphrase.txt";
static char *filename_rsa_armour_nopassphrase="gpg_signed_armour_nopassphrase.txt";
static char *filename_rsa_noarmour_passphrase="gpg_signed_armour_nopassphrase.txt";
static char *filename_rsa_armour_passphrase="gpg_signed_armour_passphrase.txt";

static ops_parse_cb_return_t
callback(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    //    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;

    //        ops_print_packet(content_);

    switch(content_->tag)
	{
    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
        break;

    case OPS_PTAG_CT_LITERAL_DATA_BODY:
        return callback_literal_data(content_,cbinfo);
        break;

    case OPS_PTAG_CT_ONE_PASS_SIGNATURE:
    case OPS_PTAG_CT_SIGNATURE:
        break;

    case OPS_PTAG_CT_SIGNATURE_HEADER:
    case OPS_PTAG_CT_SIGNATURE_FOOTER:
        return callback_signature(content_, cbinfo);

        /*
    case OPS_PTAG_CT_UNARMOURED_TEXT:
	printf("OPS_PTAG_CT_UNARMOURED_TEXT\n");
	if(!skipping)
	    {
	    puts("Skipping...");
	    skipping=ops_true;
	    }
	fwrite(content->unarmoured_text.data,1,
	       content->unarmoured_text.length,stdout);
	break;

    case OPS_PTAG_CT_PK_SESSION_KEY:
        return callback_pk_session_key(content_,cbinfo);

    case OPS_PARSER_CMD_GET_SECRET_KEY:
        return callback_cmd_get_secret_key(content_,cbinfo);

    case OPS_PARSER_CMD_GET_SK_PASSPHRASE:
        return callback_cmd_get_secret_key_passphrase(content_,cbinfo);

    case OPS_PTAG_CT_LITERAL_DATA_BODY:
        return callback_literal_data(content_,cbinfo);
        //	text=ops_mallocz(content->literal_data_body.length+1);
        //	memcpy(text,content->literal_data_body.data,content->literal_data_body.length);
        //		break;

    case OPS_PARSER_PTAG:
    case OPS_PTAG_CT_ARMOUR_HEADER:
    case OPS_PTAG_CT_ARMOUR_TRAILER:
    case OPS_PTAG_CT_ENCRYPTED_PK_SESSION_KEY:
    case OPS_PTAG_CT_COMPRESSED:
    case OPS_PTAG_CT_SE_IP_DATA_BODY:
    case OPS_PTAG_CT_SE_IP_DATA_HEADER:
	// Ignore these packets 
	// They're handled in ops_parse_one_packet()
	// and nothing else needs to be done
	break;
*/

    default:
        return callback_general(content_,cbinfo);
	}

    return OPS_RELEASE_MEMORY;
    }

/* Signature verification suite initialization.
 * Create temporary test files.
 */

int init_suite_rsa_verify(void)
    {
    char cmd[MAXBUF+1];

    // Create test files

    create_testfile(filename_rsa_noarmour_nopassphrase);
    create_testfile(filename_rsa_armour_nopassphrase);
    create_testfile(filename_rsa_noarmour_passphrase);
    create_testfile(filename_rsa_armour_passphrase);

    // Now sign the test files with GPG

    snprintf(cmd,MAXBUF,"gpg --homedir=%s --quiet --openpgp --compress-level 0 --sign --local-user %s %s/%s",
             dir, alpha_name, dir, filename_rsa_noarmour_nopassphrase);
    if (system(cmd))
        { return 1; }

    snprintf(cmd,MAXBUF,"gpg --homedir=%s --quiet --compress-level 0 --sign --armour --local-user %s %s/%s",
             dir, alpha_name, dir, filename_rsa_armour_nopassphrase);
    if (system(cmd))
        { return 1; }

    snprintf(cmd,MAXBUF,"gpg --homedir=%s --quiet --compress-level 0 --sign --local-user %s --passphrase %s %s/%s",
             dir, bravo_name, bravo_passphrase, dir, filename_rsa_noarmour_passphrase);
    if (system(cmd))
        { return 1; }

    snprintf(cmd,MAXBUF,"gpg --homedir=%s --quiet --compress-level 0 --sign --armour --local-user %s --passphrase %s %s/%s",
             dir, bravo_name, bravo_passphrase, dir, filename_rsa_armour_passphrase);
    if (system(cmd))
        { return 1; }

    // Return success
    return 0;
    }

int clean_suite_rsa_verify(void)
    {
    ops_finish();

    reset_vars();

    return 0;
    }

static void test_rsa_verify(const int has_armour, const int has_passphrase __attribute__((__unused__)), const char *filename, const char* protocol)
    {
    char signedfile[MAXBUF+1];
    //    char testtext[MAXBUF+1];
    char *suffix= has_armour ? "asc" : "gpg";
    int fd=0;
    ops_parse_info_t *pinfo=NULL;
    validate_cb_arg_t validate_arg;
    ops_validate_result_t result;
    int rtn=0;
    
    // open signed file
    snprintf(signedfile,MAXBUF,"%s/%s%s%s.%s",dir,
             protocol==NULL ? "" : protocol,
             protocol==NULL ? "" : "_",
             filename,suffix);
    fd=open(signedfile,O_RDONLY);
    if(fd < 0)
        {
        perror(signedfile);
        exit(2);
        }
    
    // Set verification reader and handling options

    pinfo=ops_parse_info_new();
    ops_parse_cb_set(pinfo,callback,&validate_arg);
    ops_reader_set_fd(pinfo,fd);

    memset(&validate_arg,'\0',sizeof validate_arg);
    validate_arg.result=&result;
    validate_arg.keyring=&pub_keyring;
    validate_arg.rarg=ops_reader_get_arg_from_pinfo(pinfo);

    // Set up armour/passphrase options

    if (has_armour)
        ops_reader_push_dearmour(pinfo,ops_false,ops_false,ops_false);
    //    current_passphrase=has_passphrase ? passphrase : nopassphrase;
    
    // Do the verification

    rtn=ops_parse(pinfo);
    CU_ASSERT(rtn==1);

    // Tidy up
    if (has_armour)
	ops_reader_pop_dearmour(pinfo);

    ops_public_key_free(&validate_arg.pkey);
    if (validate_arg.subkey.version)
        ops_public_key_free(&validate_arg.subkey);
    ops_user_id_free(&validate_arg.user_id);
    ops_user_attribute_free(&validate_arg.user_attribute);
    ops_parse_info_delete(pinfo);

    close(fd);
    
#ifdef NEEDED
    // File contents should match
    create_testtext(filename,&testtext[0],MAXBUF);
    CU_ASSERT(memcmp(literal_data,testtext,sz_literal_data)==0);
#endif
    }

void test_rsa_verify_noarmour_nopassphrase(void)
    {
    int armour=0;
    int passphrase=0;
    assert(pub_keyring.nkeys);
    //    const ops_key_data_t *pub_key=ops_keyring_find_key_by_userid(&pub_keyring, alpha_user_id);
    //    assert(pub_key);
    test_rsa_verify(armour,passphrase,filename_rsa_noarmour_nopassphrase,NULL);
    }

#ifdef TBD
void test_rsa_encrypt_armour_singlekey(void)
    {
    int armour=1;
    char *user_id="Alpha (RSA, no passphrase) <alpha@test.com>";
    const ops_key_data_t *pub_key=ops_keyring_find_key_by_userid(&pub_keyring, user_id);
    assert(pub_key);
    test_rsa_encrypt(armour,pub_key,filename_rsa_armour_singlekey);
    }

void test_rsa_encrypt_noarmour_passphrase(void)
    {
    int armour=0;
    int passphrase=1;
    test_rsa_encrypt(armour,passphrase,filename_rsa_noarmour_passphrase);
    }

void test_rsa_encrypt_armour_passphrase(void)
    {
    int armour=1;
    int passphrase=1;
    test_rsa_encrypt(armour,passphrase,filename_rsa_armour_passphrase);
    }
#endif /*TBD*/

CU_pSuite suite_rsa_verify()
{
    CU_pSuite suite = NULL;

    suite = CU_add_suite("RSA Verification Suite", init_suite_rsa_verify, clean_suite_rsa_verify);
    if (!suite)
	    return NULL;

    // add tests to suite
    
    if (NULL == CU_add_test(suite, "Unarmoured, no passphrase", test_rsa_verify_noarmour_nopassphrase))
	    return NULL;
    
    /*
    if (NULL == CU_add_test(suite, "Unarmoured, passphrase", test_rsa_verify_noarmour_passphrase))
	    return NULL;
    */
    return suite;
}

