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

static void test_rsa_signature_clearsign(const char *filename, const ops_secret_key_t *skey, ops_hash_algorithm_t hash_alg)
    {
    unsigned char keyid[OPS_KEY_ID_SIZE];
    ops_create_signature_t *sig=NULL;

    char cmd[MAXBUF+1];
    char myfile[MAXBUF+1];
    char signed_file[MAXBUF+1];
    //    char *suffix= has_armour ? "asc" : "gpg";
    char *suffix= "asc";
    int fd_in=0;
    int fd_out=0;
    int rtn=0;
    ops_create_info_t *cinfo=NULL;
    unsigned char buf[MAXBUF];
    
    // open file to sign
    snprintf(myfile,MAXBUF,"%s/%s",dir,filename);
#ifdef WIN32
    fd_in=open(myfile,O_RDONLY | O_BINARY);
#else
    fd_in=open(myfile,O_RDONLY);
#endif
    if(fd_in < 0)
        {
        perror(myfile);
        exit(2);
        }
    
    snprintf(signed_file,MAXBUF,"%s/%s_%s.%s",dir,filename,ops_show_hash_algorithm(hash_alg),suffix);
#ifdef WIN32
    fd_out=open(signed_file,O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
#else
    fd_out=open(signed_file,O_WRONLY | O_CREAT | O_EXCL, 0600);
#endif
    if(fd_out < 0)
        {
        perror(signed_file);
        exit(2);
        }
    
    // Set up armour/passphrase options
    // OPS code armours signatures by default

    //    assert(has_armour);
    
    // set up signature
    sig=ops_create_signature_new();
    ops_signature_start_plaintext_signature(sig,(ops_secret_key_t *)skey,hash_alg,OPS_SIG_BINARY);

    // set up output file
    cinfo=ops_create_info_new();
    ops_writer_set_fd(cinfo,fd_out); 
    ops_writer_push_dash_escaped(cinfo,sig);

    // Do the signing

    for (;;)
        {
        int n=0;
    
        n=read(fd_in,buf,sizeof(buf));
        if (!n)
            break;
        assert(n>=0);
        ops_write(buf,n,cinfo);
        }
    close(fd_in);

    // add signature

    ops_writer_switch_to_signature(cinfo);
    ops_signature_add_creation_time(sig,time(NULL));
    ops_keyid(keyid,&skey->public_key);
    ops_signature_add_issuer_key_id(sig,keyid);

    ops_signature_hashed_subpackets_end(sig);
    ops_write_signature(sig,(ops_public_key_t *)&skey->public_key,(ops_secret_key_t *)skey,cinfo);
    ops_writer_close(cinfo);
    close(fd_out);

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
    
    //    if (has_armour)
        ops_reader_push_dearmour(pinfo,ops_false,ops_false,ops_false);
    //    current_passphrase=has_passphrase ? passphrase : nopassphrase;
    
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

static void test_rsa_signature_noarmour_nopassphrase(void)
    {
    CU_FAIL("Test TODO: Sign file with no armour and no passphrase");
#ifdef TBD

    int armour=0;
    assert(pub_keyring.nkeys);
    test_rsa_signature(armour,filename_rsa_noarmour_nopassphrase, alpha_skey, OPS_HASH_SHA1);
#ifdef TODO
    test_rsa_signature(armour,filename_rsa_noarmour_nopassphrase, alpha_skey, OPS_HASH_MD5);
    test_rsa_signature(armour,filename_rsa_noarmour_nopassphrase, alpha_skey, OPS_HASH_RIPEMD);
    test_rsa_signature(armour,filename_rsa_noarmour_nopassphrase, alpha_skey, OPS_HASH_SHA256);
    test_rsa_signature(armour,filename_rsa_noarmour_nopassphrase, alpha_skey, OPS_HASH_SHA384);
    test_rsa_signature(armour,filename_rsa_noarmour_nopassphrase, alpha_skey, OPS_HASH_SHA512);
#endif
#endif
    }

static void test_rsa_signature_noarmour_passphrase(void)
    {
    CU_FAIL("Test TODO: Sign file with no armour and passphrase");
#ifdef TBD
    int armour=0;
    assert(pub_keyring.nkeys);
    test_rsa_signature(armour,filename_rsa_noarmour_passphrase, bravo_skey, OPS_HASH_SHA1);
#endif
    }

static void test_rsa_signature_armour_nopassphrase(void)
    {
    CU_FAIL("Test TODO: Sign file with armour and no passphrase");
#ifdef TBD
    int armour=1;
    assert(pub_keyring.nkeys);
    test_rsa_signature(armour,filename_rsa_armour_nopassphrase, alpha_skey, OPS_HASH_SHA1);
#endif
    }

static void test_rsa_signature_armour_passphrase(void)
    {
    CU_FAIL("Test TODO: Sign file with armour and passphrase");
#ifdef TBD
    int armour=1;
    assert(pub_keyring.nkeys);
    test_rsa_signature(armour,filename_rsa_armour_passphrase, bravo_skey, OPS_HASH_SHA1);
#endif
    }

static void test_rsa_signature_clearsign_nopassphrase(void)
    {
    assert(pub_keyring.nkeys);
    test_rsa_signature_clearsign(filename_rsa_armour_nopassphrase, alpha_skey, OPS_HASH_SHA1);
    }

static void test_rsa_signature_clearsign_passphrase(void)
    {
    assert(pub_keyring.nkeys);
    test_rsa_signature_clearsign(filename_rsa_armour_passphrase, bravo_skey, OPS_HASH_SHA1);
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
    
    if (NULL == CU_add_test(suite, "Armoured, no passphrase", test_rsa_signature_armour_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Armoured, passphrase", test_rsa_signature_armour_passphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Clearsigned, no passphrase", test_rsa_signature_clearsign_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Clearsigned, passphrase", test_rsa_signature_clearsign_passphrase))
	    return NULL;
    
    return suite;
}

// EOF
