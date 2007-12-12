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

// \todo change this once we know it works
#include "../src/advanced/parse_local.h"

#include "tests.h"

#ifndef ATTRIBUTE_UNUSED

#ifndef WIN32
#define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
#else
#define ATTRIBUTE_UNUSED 
#endif // #ifndef WIN32

#endif /* ATTRIBUTE_UNUSED */

static char *filename_rsa_armour_nopassphrase="gpg_signed_armour_nopassphrase.txt";
static char *filename_rsa_armour_passphrase="gpg_signed_armour_passphrase.txt";

static char *filename_rsa_noarmour_nopassphrase="gpg_signed_noarmour_nopassphrase.txt";
static char *filename_rsa_noarmour_passphrase="gpg_signed_noarmour_passphrase.txt";

static char *filename_rsa_clearsign_nopassphrase="gpg_clearsigned_nopassphrase.txt";
static char *filename_rsa_clearsign_passphrase="gpg_clearsigned_passphrase.txt";

/* Signature verification suite initialization.
 * Create temporary test files.
 */

int init_suite_rsa_verify(void)
    {
    char cmd[MAXBUF+1];

    // Create SIGNED test files

    create_testfile(filename_rsa_armour_nopassphrase);
    create_testfile(filename_rsa_armour_passphrase);

    create_testfile(filename_rsa_noarmour_nopassphrase);
    create_testfile(filename_rsa_noarmour_passphrase);

    // Now sign the test files with GPG

    snprintf(cmd,MAXBUF,"%s --openpgp --compress-level 0 --sign --local-user %s %s/%s",
             gpgcmd, alpha_name, dir, filename_rsa_noarmour_nopassphrase);
    if (system(cmd))
        { return 1; }

    snprintf(cmd,MAXBUF,"%s --openpgp --compress-level 0 --sign --local-user %s --armor %s/%s",
             gpgcmd, alpha_name, dir, filename_rsa_armour_nopassphrase);
    if (system(cmd))
        { return 1; }

    snprintf(cmd,MAXBUF,"%s --openpgp --compress-level 0 --sign --local-user %s --passphrase %s %s/%s",
             gpgcmd, bravo_name, bravo_passphrase, dir, filename_rsa_noarmour_passphrase);
    if (system(cmd))
        { return 1; }

    snprintf(cmd,MAXBUF,"%s --openpgp --compress-level 0 --sign --local-user %s --passphrase %s --armor %s/%s",
             gpgcmd, bravo_name, bravo_passphrase, dir, filename_rsa_armour_passphrase);
    if (system(cmd))
        { return 1; }

    /*
     * Create CLEARSIGNED test files
     */

    create_testfile(filename_rsa_clearsign_nopassphrase);
    create_testfile(filename_rsa_clearsign_passphrase);

    // and sign them

    snprintf(cmd,MAXBUF,"%s --openpgp --compress-level 0 --clearsign --textmode --local-user %s --armor %s/%s",
             gpgcmd, alpha_name, dir, filename_rsa_clearsign_nopassphrase);
    if (system(cmd))
        { return 1; }

    snprintf(cmd,MAXBUF,"%s --openpgp --compress-level 0 --clearsign --textmode --local-user %s --passphrase %s --armor %s/%s",
             gpgcmd, bravo_name, bravo_passphrase, dir, filename_rsa_clearsign_passphrase);
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

static void test_rsa_verify(const int has_armour, const int has_passphrase ATTRIBUTE_UNUSED, const char *filename, const char* protocol)
    {
    char signedfile[MAXBUF+1];
    char *suffix= has_armour ? "asc" : "gpg";
    int fd=0;
    ops_parse_info_t *pinfo=NULL;
    validate_data_cb_arg_t validate_arg;
    ops_validate_result_t result;
    int rtn=0;
    
    // open signed file
    snprintf(signedfile,MAXBUF,"%s/%s%s%s.%s",
             dir, filename,
             protocol==NULL ? "" : "_",
             protocol==NULL ? "" : protocol,
             suffix);
#ifdef WIN32
    fd=open(signedfile,O_RDONLY | O_BINARY);
#else
    fd=open(signedfile,O_RDONLY);
#endif
    if(fd < 0)
        {
        perror(signedfile);
        exit(2);
        }
    
    // Set verification reader and handling options

    pinfo=ops_parse_info_new();

    memset(&validate_arg,'\0',sizeof validate_arg);
    validate_arg.result=&result;
    validate_arg.keyring=&pub_keyring;
    validate_arg.rarg=ops_reader_get_arg_from_pinfo(pinfo);

    ops_parse_cb_set(pinfo,callback_verify,&validate_arg);
    ops_reader_set_fd(pinfo,fd);
    pinfo->rinfo.accumulate=ops_true;

    // Set up armour/passphrase options

    if (has_armour)
        ops_reader_push_dearmour(pinfo,ops_false,ops_false,ops_false);
    //    current_passphrase=has_passphrase ? passphrase : nopassphrase;
    
    // Do the verification

    rtn=ops_parse(pinfo);
    ops_print_errors(ops_parse_info_get_errors(pinfo));
    CU_ASSERT(rtn==1);

    // Tidy up
    if (has_armour)
	ops_reader_pop_dearmour(pinfo);

    ops_parse_info_delete(pinfo);

    close(fd);
    
#ifdef NEEDED
    // File contents should match
    create_testtext(filename,&testtext[0],MAXBUF);
    CU_ASSERT(memcmp(literal_data,testtext,sz_literal_data)==0);
#endif
    }

static void test_rsa_verify_noarmour_nopassphrase(void)
    {
    //    int clearsign=0;
    int armour=0;
    int passphrase=0;
    assert(pub_keyring.nkeys);
    //    const ops_key_data_t *pub_key=ops_keyring_find_key_by_userid(&pub_keyring, alpha_user_id);
    //    assert(pub_key);
    test_rsa_verify(armour,passphrase,filename_rsa_noarmour_nopassphrase,NULL);
    }

static void test_rsa_verify_noarmour_passphrase(void)
    {
    //    int clearsign=0;
    int armour=0;
    int passphrase=1;
    assert(pub_keyring.nkeys);
    test_rsa_verify(armour,passphrase,filename_rsa_noarmour_passphrase,NULL);
    }

static void test_rsa_verify_armour_nopassphrase(void)
    {
    int armour=1;
    int passphrase=0;
    assert(pub_keyring.nkeys);
    test_rsa_verify(armour,passphrase,filename_rsa_armour_nopassphrase,NULL);
    }

static void test_rsa_verify_armour_passphrase(void)
    {
    int armour=1;
    int passphrase=1;
    assert(pub_keyring.nkeys);
    test_rsa_verify(armour,passphrase,filename_rsa_armour_passphrase,NULL);
    }

static void test_rsa_verify_clearsign_nopassphrase(void)
    {
    //    int clearsign=1;
    int armour=1;
    int passphrase=0;
    assert(pub_keyring.nkeys);

    test_rsa_verify(armour,passphrase,filename_rsa_clearsign_nopassphrase,NULL);
    }

static void test_rsa_verify_clearsign_passphrase(void)
    {
    //    int clearsign=1;
    int armour=1;
    int passphrase=1;
    assert(pub_keyring.nkeys);

    test_rsa_verify(armour,passphrase,filename_rsa_clearsign_passphrase,NULL);
    }


CU_pSuite suite_rsa_verify()
{
    CU_pSuite suite = NULL;

    suite = CU_add_suite("RSA Verification Suite", init_suite_rsa_verify, clean_suite_rsa_verify);
    if (!suite)
	    return NULL;

    // add tests to suite
    
    if (NULL == CU_add_test(suite, "Clearsigned, no passphrase", test_rsa_verify_clearsign_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Clearsigned, passphrase", test_rsa_verify_clearsign_passphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Armoured, no passphrase", test_rsa_verify_armour_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Armoured, passphrase", test_rsa_verify_armour_passphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Unarmoured, no passphrase", test_rsa_verify_noarmour_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Unarmoured, passphrase", test_rsa_verify_noarmour_passphrase))
	    return NULL;

    return suite;
}

// EOF
