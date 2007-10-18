#include "CUnit/Basic.h"
 
#include <openpgpsdk/types.h>
#include "openpgpsdk/keyring.h"
#include <openpgpsdk/armour.h>
#include "openpgpsdk/packet.h"
#include "openpgpsdk/packet-parse.h"
#include "openpgpsdk/util.h"
#include "openpgpsdk/std_print.h"
#include "openpgpsdk/readerwriter.h"

#include "tests.h"

static int do_gpgtest=0;

static char *filename_rsa_noarmour_nopassphrase_singlekey="enc_rsa_noarmour_np_singlekey.txt";
static char *filename_rsa_noarmour_passphrase_singlekey="enc_rsa_noarmour_pp_singlekey.txt";
static char *filename_rsa_armour_singlekey="enc_rsa_armour_singlekey.txt";

static ops_parse_cb_return_t
callback_ops_decrypt(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;
    static ops_boolean_t skipping;

    OPS_USED(cbinfo);

//    ops_print_packet(content_);

    if(content_->tag != OPS_PTAG_CT_UNARMOURED_TEXT && skipping)
	{
	puts("...end of skip");
	skipping=ops_false;
	}

    switch(content_->tag)
	{
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

    case OPS_PARSER_PTAG:
    case OPS_PTAG_CT_ARMOUR_HEADER:
    case OPS_PTAG_CT_ARMOUR_TRAILER:
    case OPS_PTAG_CT_ENCRYPTED_PK_SESSION_KEY:
    case OPS_PTAG_CT_COMPRESSED:
    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
    case OPS_PTAG_CT_SE_IP_DATA_BODY:
    case OPS_PTAG_CT_SE_IP_DATA_HEADER:
	// Ignore these packets 
	// They're handled in ops_parse_one_packet()
	// and nothing else needs to be done
	break;

    default:
        return callback_general(content_,cbinfo);
	}

    return OPS_RELEASE_MEMORY;
    }

/* Decryption suite initialization.
 * Create temporary directory.
 * Create temporary test files.
 */

int init_suite_rsa_encrypt(void)
    {
    do_gpgtest=0;

    // Create RSA test files

    create_testfile(filename_rsa_noarmour_nopassphrase_singlekey);
    create_testfile(filename_rsa_noarmour_passphrase_singlekey);
    create_testfile(filename_rsa_armour_singlekey);
    /*
    create_testfile(filename_rsa_noarmour_passphrase);
    create_testfile(filename_rsa_armour_passphrase);
    */

    // Return success
    return 0;
    }

int init_suite_rsa_encrypt_gpgtest(void)
    {
    init_suite_rsa_encrypt();

    do_gpgtest=1;

    return 0;
    }

int clean_suite_rsa_encrypt(void)
    {
	
    ops_finish();

    reset_vars();

    return 0;
    }

static int test_rsa_decrypt(const char *encfile, const char*testtext)
    {
    int fd=0;
    ops_parse_info_t *pinfo;
    int rtn=0;

    // open encrypted file
#ifdef WIN32
    fd=open(encfile,O_RDONLY | O_BINARY);
#else
    fd=open(encfile,O_RDONLY);
#endif
    if(fd < 0)
        {
        perror(encfile);
        exit(2);
        }
    
    // Set decryption reader and handling options

    pinfo=ops_parse_info_new();
    ops_reader_set_fd(pinfo,fd);
    ops_parse_cb_set(pinfo,callback_ops_decrypt,NULL);

    // Do the decryption

    ops_memory_init(mem_literal_data,0);
    rtn=ops_parse(pinfo);
    ops_print_errors(ops_parse_info_get_errors(pinfo));
    CU_ASSERT(rtn==1);

    // Tidy up

    close(fd);
    
    // File contents should match

    CU_ASSERT(memcmp(ops_memory_get_data(mem_literal_data),testtext,ops_memory_get_length(mem_literal_data))==0);

    return rtn;
    }

static void test_rsa_encrypt(const int has_armour, const ops_key_data_t *pub_key, const char *filename)
    {
    char cmd[MAXBUF+1];
    char myfile[MAXBUF+1];
    char encrypted_file[MAXBUF+1];
    char decrypted_file[MAXBUF+1];
    char *suffix= has_armour ? "asc" : "gpg";
    char *gpgtest = do_gpgtest ? "gpgtest_" : "";
    int fd_in=0;
    int fd_out=0;
    int rtn=0;
    
    ops_create_info_t *cinfo;
    char* testtext=NULL;
    char pp[MAXBUF];

    /*
     * Read from test file and write plaintext to memory
     * in set of Literal Data packets
     */

    // open file to encrypt
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
    
    snprintf(encrypted_file,MAXBUF,"%s/%s%s.%s",dir,gpgtest,filename,suffix);
#ifdef WIN32
    fd_out=open(encrypted_file,O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
#else
    fd_out=open(encrypted_file,O_WRONLY | O_CREAT | O_EXCL, 0600);
#endif
    if(fd_out < 0)
        {
        perror(encrypted_file);
        exit(2);
        }
    
    /*
     * This shows how to use encryption
     */

    // Do setup for encrypted writing
    // This example shows output to a file

    cinfo=ops_create_info_new();
    ops_writer_set_fd(cinfo,fd_out); 

    // Push the encrypted writer
    ops_writer_push_encrypt_se_ip(cinfo,pub_key);

    // Do the writing

    unsigned char* buf=NULL;
    size_t bufsz=16;
    int done=0;
    for (;;)
        {
        buf=realloc(buf,done+bufsz);
        
	    int n=0;

	    n=read(fd_in,buf+done,bufsz);
	    if (!n)
		    break;
	    assert(n>=0);
        done+=n;
        }

    // This does the writing
    ops_write(buf,done,cinfo);

    // Pop the encrypted writer from the stack
    ops_writer_pop(cinfo);

    // tidy up
    close(fd_in);
    close(fd_out);

    /*
     * Encryption complete
     */

    /*
     * Test results
     */

    if (do_gpgtest)
        {
        // File contents should match - check with GPG
        
        if (pub_key==alpha_pub_keydata)
            pp[0]='\0';
        else if (pub_key==bravo_pub_keydata)
            snprintf(pp,MAXBUF," --passphrase %s ", bravo_passphrase);
        snprintf(decrypted_file,MAXBUF,"%s/decrypted_%s",dir,filename);
        snprintf(cmd,MAXBUF,"gpg --decrypt --output=%s --quiet --homedir %s %s %s",decrypted_file, dir, pp, encrypted_file);
        //    printf("cmd: %s\n", cmd);
        rtn=system(cmd);
        CU_ASSERT(rtn==0);
        CU_ASSERT(file_compare(myfile,decrypted_file)==0);
        }
    else
        {
        // File contents should match - checking with OPS
        
        testtext=create_testtext(filename);
        test_rsa_decrypt(encrypted_file,testtext);
        }
    }

static void test_rsa_encrypt_noarmour_nopassphrase_singlekey(void)
    {
    int armour=0;
    test_rsa_encrypt(armour,alpha_pub_keydata,filename_rsa_noarmour_nopassphrase_singlekey);
    }

static void test_rsa_encrypt_noarmour_passphrase_singlekey(void)
    {
    int armour=0;
    test_rsa_encrypt(armour,bravo_pub_keydata,filename_rsa_noarmour_passphrase_singlekey);
    }

static void test_rsa_encrypt_armour_nopassphrase_singlekey(void)
    {
    CU_FAIL("Test TODO: Encrypt with armour/no passphrase/single-key");
#ifdef TBD
    int armour=1;
    char *user_id="Alpha (RSA, no passphrase) <alpha@test.com>";
    const ops_key_data_t *pub_key=ops_keyring_find_key_by_userid(&pub_keyring, user_id);
    assert(pub_key);
    test_rsa_encrypt(armour,pub_key,filename_rsa_armour_singlekey);
#endif
    }

static void test_rsa_encrypt_armour_passphrase_singlekey(void)
    {
    CU_FAIL("Test TODO: Encrypt with armour/passphrase/single-key");
#ifdef TBD
    int armour=1;
    int passphrase=1;
    test_rsa_encrypt(armour,passphrase,filename_rsa_armour_passphrase);
#endif
    }

static void test_todo(void)
    {
    CU_FAIL("Test TODO: Encrypt to multiple keys in same keyring");
    CU_FAIL("Test TODO: Encrypt to multiple keys where my keys is (a) first key in list; (b) last key in list; (c) in the middle of the list");
    CU_FAIL("Test TODO: Encrypt to users with different preferences");
    }

int add_tests(CU_pSuite suite)
    {
    // add tests to suite
    
    if (NULL == CU_add_test(suite, "Unarmoured, single key, no passphrase", test_rsa_encrypt_noarmour_nopassphrase_singlekey))
	    return 0;
    
    if (NULL == CU_add_test(suite, "Unarmoured, single key, passphrase", test_rsa_encrypt_noarmour_passphrase_singlekey))
	    return 0;
    
    if (NULL == CU_add_test(suite, "Armoured, single key, no passphrase", test_rsa_encrypt_armour_nopassphrase_singlekey))
	    return 0;
    
    if (NULL == CU_add_test(suite, "Armoured, single key, passphrase", test_rsa_encrypt_armour_passphrase_singlekey))
	    return 0;

    if (NULL == CU_add_test(suite, "Tests to be implemented", test_todo))
	    return 0;
    
    return 1;
    }
    
CU_pSuite suite_rsa_encrypt()
    {
    CU_pSuite suite = NULL;

    suite = CU_add_suite("RSA Encryption Suite", init_suite_rsa_encrypt, clean_suite_rsa_encrypt);
    if (!suite)
	    return NULL;

    if (!add_tests(suite))
        return NULL;

    return suite;
    }

CU_pSuite suite_rsa_encrypt_GPGtest()
    {
    CU_pSuite suite = NULL;

    suite = CU_add_suite("RSA Encryption Suite (GPG interoperability)", init_suite_rsa_encrypt_gpgtest, clean_suite_rsa_encrypt);

    if (!suite)
	    return NULL;

    if (!add_tests(suite))
        return NULL;

    return suite;
    }

// EOF
