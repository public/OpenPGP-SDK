#include "CUnit/Basic.h"

#include <openpgpsdk/types.h>
#include "openpgpsdk/keyring.h"
#include <openpgpsdk/armour.h>
#include "openpgpsdk/packet.h"
#include "openpgpsdk/packet-parse.h"
#include "openpgpsdk/packet-show.h"
#include "openpgpsdk/util.h"
#include "openpgpsdk/std_print.h"
#include "openpgpsdk/readerwriter.h"
#include "openpgpsdk/validate.h"

// \todo change this once we know it works
#include "../src/advanced/parse_local.h"

#include "tests.h"

static int debug=0;

static char *filename_rsa_noarmour_nopassphrase="ops_rsa_signed_noarmour_nopassphrase.txt";
static char *filename_rsa_noarmour_passphrase="ops_rsa_signed_noarmour_passphrase.txt";
static char *filename_rsa_armour_nopassphrase="ops_rsa_signed_armour_nopassphrase.txt";
static char *filename_rsa_armour_passphrase="ops_rsa_signed_armour_passphrase.txt";
static char *filename_rsa_clearsign_nopassphrase="ops_rsa_signed_clearsign_nopassphrase.txt";
static char *filename_rsa_clearsign_passphrase="ops_rsa_signed_clearsign_passphrase.txt";

/* Signature suite initialization.
 * Create temporary directory.
 * Create temporary test files.
 */

int init_suite_rsa_signature(void)
    {
    // Create test files

    create_testfile(filename_rsa_noarmour_nopassphrase);
    create_testfile(filename_rsa_noarmour_passphrase);
    create_testfile(filename_rsa_armour_nopassphrase);
    create_testfile(filename_rsa_armour_passphrase);
    create_testfile(filename_rsa_clearsign_nopassphrase);
    create_testfile(filename_rsa_clearsign_passphrase);

    // Return success
    return 0;
    }

int clean_suite_rsa_signature(void)
    {
    ops_finish();

    reset_vars();

    return 0;
    }

static void test_rsa_signature_clearsign(const char *filename, const ops_secret_key_t *skey)
    {
    char cmd[MAXBUF+1];
    char myfile[MAXBUF+1];
    char signed_file[MAXBUF+1];
    int rtn=0;

    // setup filenames
    snprintf(myfile,MAXBUF,"%s/%s",dir,filename);
    snprintf(signed_file,MAXBUF,"%s.asc",myfile);

    // sign file
    ops_sign_file_as_cleartext(myfile,skey);

    /*
     * Validate output
     */

    // Check with OPS

    {
    int fd=0;
    ops_parse_info_t *pinfo=NULL;
    validate_data_cb_arg_t validate_arg;
    ops_validate_result_t result;
    int rtn=0;
    
    if (debug)
        {
        fprintf(stderr,"\n***\n*** Starting to parse for validation\n***\n");
        }
    
    // open signed file
#ifdef WIN32
    fd=open(signed_file,O_RDONLY | O_BINARY);
#else
    fd=open(signed_file,O_RDONLY);
#endif
    if(fd < 0)
        {
        perror(signed_file);
        exit(2);
        }
    
    // Set verification reader and handling options
    
    pinfo=ops_parse_info_new();
    
    memset(&validate_arg,'\0',sizeof validate_arg);
    validate_arg.result=&result;
    validate_arg.keyring=&pub_keyring;
    validate_arg.rarg=ops_reader_get_arg_from_pinfo(pinfo);
    
    ops_parse_options(pinfo,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);
    ops_parse_cb_set(pinfo,callback_verify,&validate_arg);
    ops_reader_set_fd(pinfo,fd);
    pinfo->rinfo.accumulate=ops_true;
    
    // Must de-armour because it's clearsigned
    
    ops_reader_push_dearmour(pinfo,ops_false,ops_false,ops_false);
    
    // Do the verification
    
    rtn=ops_parse(pinfo);
    ops_print_errors(ops_parse_info_get_errors(pinfo));
    CU_ASSERT(rtn==1);
    
    // Tidy up
    //    if (has_armour)
        ops_reader_pop_dearmour(pinfo);
    
    ops_parse_info_delete(pinfo);
    
    close(fd);
    }

    // Check signature with GPG
    {

    snprintf(cmd,MAXBUF,"%s --verify %s", gpgcmd, signed_file);
    rtn=system(cmd);
    CU_ASSERT(rtn==0);
    }
    }

static void test_rsa_signature_sign(const int use_armour, const char *filename, const ops_secret_key_t *skey)
    {
    char cmd[MAXBUF+1];
    char myfile[MAXBUF+1];
    char signed_file[MAXBUF+1];
    char *suffix= use_armour ? "asc" : "ops";
    int rtn=0;

    // filenames
    snprintf(myfile,MAXBUF,"%s/%s",dir,filename);
    snprintf(signed_file,MAXBUF,"%s.%s",myfile,suffix);

    ops_sign_file(myfile, signed_file, skey, use_armour);

    /*
     * Validate output
     */

    // Check with OPS

    {
    int fd=0;
    ops_parse_info_t *pinfo=NULL;
    validate_data_cb_arg_t validate_arg;
    ops_validate_result_t result;
    int rtn=0;
    
    if (debug)
        {
        fprintf(stderr,"\n***\n*** Starting to parse for validation\n***\n");
        }
    
    // open signed file
#ifdef WIN32
    fd=open(signed_file,O_RDONLY | O_BINARY);
#else
    fd=open(signed_file,O_RDONLY);
#endif
    if(fd < 0)
        {
        perror(signed_file);
        exit(2);
        }
    
    // Set verification reader and handling options
    
    pinfo=ops_parse_info_new();
    
    memset(&validate_arg,'\0',sizeof validate_arg);
    validate_arg.result=&result;
    validate_arg.keyring=&pub_keyring;
    validate_arg.rarg=ops_reader_get_arg_from_pinfo(pinfo);
    
    ops_parse_options(pinfo,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);
    ops_parse_cb_set(pinfo,callback_verify,&validate_arg);
    ops_reader_set_fd(pinfo,fd);
    pinfo->rinfo.accumulate=ops_true;
    
    // Set up armour/passphrase options
    
    if (use_armour)
        ops_reader_push_dearmour(pinfo,ops_false,ops_false,ops_false);
    
    // Do the verification
    
    rtn=ops_parse(pinfo);
    ops_print_errors(ops_parse_info_get_errors(pinfo));
    CU_ASSERT(rtn==1);
    
    // Tidy up
    if (use_armour)
        ops_reader_pop_dearmour(pinfo);
    
    ops_parse_info_delete(pinfo);
    
    close(fd);
    }

    // Check signature with GPG
    {

    snprintf(cmd,MAXBUF,"%s --verify %s", gpgcmd, signed_file);
    rtn=system(cmd);
    CU_ASSERT(rtn==0);
    }
    }

static void test_rsa_signature_noarmour_nopassphrase(void)
    {
    int armour=0;
    assert(pub_keyring.nkeys);
    test_rsa_signature_sign(armour,filename_rsa_noarmour_nopassphrase, alpha_skey);
    }

static void test_rsa_signature_noarmour_passphrase(void)
    {
    int armour=0;
    assert(pub_keyring.nkeys);
    test_rsa_signature_sign(armour,filename_rsa_noarmour_passphrase, bravo_skey);
    }

static void test_rsa_signature_armour_nopassphrase(void)
    {
    int armour=1;
    assert(pub_keyring.nkeys);
    test_rsa_signature_sign(armour,filename_rsa_armour_nopassphrase, alpha_skey);
    }

static void test_rsa_signature_armour_passphrase(void)
    {
    int armour=1;
    assert(pub_keyring.nkeys);
    test_rsa_signature_sign(armour,filename_rsa_armour_passphrase, bravo_skey);
    }

static void test_rsa_signature_clearsign_nopassphrase(void)
    {
    assert(pub_keyring.nkeys);
    test_rsa_signature_clearsign(filename_rsa_clearsign_nopassphrase, alpha_skey);
    }

static void test_rsa_signature_clearsign_passphrase(void)
    {
    assert(pub_keyring.nkeys);
    test_rsa_signature_clearsign(filename_rsa_clearsign_passphrase, bravo_skey);
    }

CU_pSuite suite_rsa_signature()
{
    CU_pSuite suite = NULL;

    suite = CU_add_suite("RSA Signature Suite", init_suite_rsa_signature, clean_suite_rsa_signature);
    if (!suite)
	    return NULL;

    // add tests to suite
    
    if (NULL == CU_add_test(suite, "Unarmoured, no passphrase", test_rsa_signature_noarmour_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Unarmoured, passphrase", test_rsa_signature_noarmour_passphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Clearsigned, no passphrase", test_rsa_signature_clearsign_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Clearsigned, passphrase", test_rsa_signature_clearsign_passphrase))
	    return NULL;

    if (NULL == CU_add_test(suite, "Armoured, no passphrase", test_rsa_signature_armour_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Armoured, passphrase", test_rsa_signature_armour_passphrase))
	    return NULL;
    
    return suite;
}

// EOF
