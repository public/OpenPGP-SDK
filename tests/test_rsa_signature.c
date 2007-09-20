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

#include "tests.h"

static char *filename_rsa_noarmour_nopassphrase="ops_rsa_signed_noarmour_nopassphrase.txt";
static char *filename_rsa_noarmour_passphrase="ops_rsa_signed_noarmour_passphrase.txt";
static char *filename_rsa_armour_nopassphrase="ops_rsa_signed_armour_nopassphrase.txt";
static char *filename_rsa_armour_passphrase="ops_rsa_signed_armour_passphrase.txt";

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

    // Return success
    return 0;
    }

int clean_suite_rsa_signature(void)
    {
    ops_finish();

    reset_vars();

    return 0;
    }

static void test_rsa_signature(const int has_armour, const char *filename, const ops_secret_key_t *skey, ops_hash_algorithm_t hash_alg)
    {
    unsigned char keyid[OPS_KEY_ID_SIZE];
    ops_create_signature_t *sig=NULL;

    char cmd[MAXBUF+1];
    char myfile[MAXBUF+1];
    char signed_file[MAXBUF+1];
    char *suffix= has_armour ? "asc" : "gpg";
    int fd_in=0;
    int fd_out=0;
    int rtn=0;
    
    // open file to sign
    snprintf(myfile,MAXBUF,"%s/%s",dir,filename);
    fd_in=open(myfile,O_RDONLY);
    if(fd_in < 0)
        {
        perror(myfile);
        exit(2);
        }
    
    snprintf(signed_file,MAXBUF,"%s/%s_%s.%s",dir,filename,ops_show_hash_algorithm(hash_alg),suffix);
    fd_out=open(signed_file,O_WRONLY | O_CREAT | O_EXCL, 0600);
    if(fd_out < 0)
        {
        perror(signed_file);
        exit(2);
        }
    
    // Set up armour/passphrase options
    // OPS code armours signatures by default

    assert(has_armour);
    
    // set up signature
    sig=ops_create_signature_new();
    ops_signature_start_plaintext_signature(sig,(ops_secret_key_t *)skey,hash_alg,OPS_SIG_BINARY);

    // set up output file
    ops_create_info_t *cinfo;
    cinfo=ops_create_info_new();
    ops_writer_set_fd(cinfo,fd_out); 
    ops_writer_push_dash_escaped(cinfo,sig);

    // Do the signing

    for (;;)
        {
        unsigned char buf[MAXBUF];
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

#ifdef TODO
     // Check signature with OPS
#endif

    // Check signature with GPG

    snprintf(cmd,MAXBUF,"gpg --verify --quiet --homedir %s %s", dir, signed_file);
    rtn=system(cmd);
    CU_ASSERT(rtn==0);
    }

void test_rsa_signature_noarmour_nopassphrase(void)
    {
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
    }

void test_rsa_signature_noarmour_passphrase(void)
    {
    int armour=0;
    assert(pub_keyring.nkeys);
    test_rsa_signature(armour,filename_rsa_noarmour_passphrase, bravo_skey, OPS_HASH_SHA1);
    }

void test_rsa_signature_armour_nopassphrase(void)
    {
    int armour=1;
    assert(pub_keyring.nkeys);
    test_rsa_signature(armour,filename_rsa_armour_nopassphrase, alpha_skey, OPS_HASH_SHA1);
    }

void test_rsa_signature_armour_passphrase(void)
    {
    int armour=1;
    assert(pub_keyring.nkeys);
    test_rsa_signature(armour,filename_rsa_armour_passphrase, bravo_skey, OPS_HASH_SHA1);
    }

CU_pSuite suite_rsa_signature()
{
    CU_pSuite suite = NULL;

    suite = CU_add_suite("RSA Signature Suite", init_suite_rsa_signature, clean_suite_rsa_signature);
    if (!suite)
	    return NULL;

    // add tests to suite
    
#ifdef TBD
    if (NULL == CU_add_test(suite, "Unarmoured, no passphrase", test_rsa_signature_noarmour_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Unarmoured, passphrase", test_rsa_signature_noarmour_passphrase))
	    return NULL;
#endif /*TBD*/
    
    if (NULL == CU_add_test(suite, "Armoured, no passphrase", test_rsa_signature_armour_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Armoured, passphrase", test_rsa_signature_armour_passphrase))
	    return NULL;
    
    
    return suite;
}

