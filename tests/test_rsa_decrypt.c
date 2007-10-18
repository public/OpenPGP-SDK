#include "tests.h"

#include "CUnit/Basic.h"

#include <openpgpsdk/types.h>
#include "openpgpsdk/keyring.h"
#include <openpgpsdk/armour.h>
#include "openpgpsdk/packet.h"
#include "openpgpsdk/packet-parse.h"
#include "openpgpsdk/util.h"
#include "openpgpsdk/std_print.h"

/* 
These include files are needed by callback.
To be removed when callback gets added to main body of code
*/
#include "../src/advanced/parse_local.h"
#include "../src/advanced/keyring_local.h"

static char *filename_rsa_noarmour_nopassphrase="dec_rsa_noarmour_nopassphrase.txt";

static char *filename_rsa_armour_nopassphrase="dec_rsa_armour_nopassphrase.txt";
static char *filename_rsa_noarmour_passphrase="dec_rsa_noarmour_passphrase.txt";
static char *filename_rsa_armour_passphrase="dec_rsa_armour_passphrase.txt";
static char *nopassphrase="";
static char *current_passphrase=NULL;

static ops_parse_cb_return_t
callback(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;
    static ops_boolean_t skipping;
    //    static const ops_key_data_t *decrypter;
    //    const ops_key_data_t *keydata=NULL;
    //    const ops_secret_key_t *secret;

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
        break;

    case OPS_PARSER_CMD_GET_SECRET_KEY:
        return callback_cmd_get_secret_key(content_,cbinfo);
        break;

    case OPS_PARSER_CMD_GET_SK_PASSPHRASE:
        return callback_cmd_get_secret_key_passphrase(content_,cbinfo);
        break;

    case OPS_PTAG_CT_LITERAL_DATA_BODY:
        return callback_literal_data(content_,cbinfo);
		break;

    case OPS_PTAG_CT_ARMOUR_HEADER:
    case OPS_PTAG_CT_ARMOUR_TRAILER:
    case OPS_PTAG_CT_ENCRYPTED_PK_SESSION_KEY:
    case OPS_PTAG_CT_COMPRESSED:
    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
    case OPS_PTAG_CT_SE_IP_DATA_BODY:
    case OPS_PTAG_CT_SE_IP_DATA_HEADER:
    case OPS_PTAG_CT_SE_DATA_BODY:
    case OPS_PTAG_CT_SE_DATA_HEADER:

	// Ignore these packets 
	// They're handled in ops_parse_one_packet()
	// and nothing else needs to be done
	break;

    default:
        return callback_general(content_,cbinfo);
        //	fprintf(stderr,"Unexpected packet tag=%d (0x%x)\n",content_->tag,
        //		content_->tag);
        //	assert(0);
	}

    return OPS_RELEASE_MEMORY;
    }

/* Decryption suite initialization.
 * Create temporary directory.
 * Create temporary test files.
 */

int init_suite_rsa_decrypt(void)
    {
    char cmd[MAXBUF+1];

    // Create RSA test files

    create_testfile(filename_rsa_noarmour_nopassphrase);
    create_testfile(filename_rsa_armour_nopassphrase);
    create_testfile(filename_rsa_noarmour_passphrase);
    create_testfile(filename_rsa_armour_passphrase);

    /*
     * Now encrypt the test files with GPG
     * Note:: To make it do SE_IP packets, do NOT use --openpgp and DO use --force-mdc
     */

    // default symmetric algorithm
    snprintf(cmd,MAXBUF,"gpg --homedir=%s --force-mdc --compress-level 0 --quiet --encrypt --recipient Alpha %s/%s", dir, dir, filename_rsa_noarmour_nopassphrase);
    if (system(cmd))
        {
        return 1;
        }

#ifndef OPENSSL_NO_IDEA
    // \todo write test which uses PGP2 instead of using gpg to test IDEA
    /*
    // IDEA
    snprintf(cmd,MAXBUF,"gpg --homedir=%s --cipher-algo \"IDEA\" --output=%s/IDEA_%s.gpg  --force-mdc --compress-level 0 --quiet --encrypt --recipient Alpha %s/%s", dir, dir, filename_rsa_noarmour_nopassphrase, dir, filename_rsa_noarmour_nopassphrase);
    if (system(cmd))
        {
        return 1;
        }
    */
#endif

    // TripleDES 
    snprintf(cmd,MAXBUF,"gpg --homedir=%s --cipher-algo \"3DES\" --output=%s/3DES_%s.gpg  --force-mdc --compress-level 0 --quiet --encrypt --recipient Alpha %s/%s", dir, dir, filename_rsa_noarmour_nopassphrase, dir, filename_rsa_noarmour_nopassphrase);
    if (system(cmd))
        {
        return 1;
        }

    // Cast5
    snprintf(cmd,MAXBUF,"gpg --homedir=%s --cipher-algo \"CAST5\" --output=%s/CAST5_%s.gpg  --force-mdc --compress-level 0 --quiet --encrypt --recipient Alpha %s/%s", dir, dir, filename_rsa_noarmour_nopassphrase, dir, filename_rsa_noarmour_nopassphrase);
    if (system(cmd))
        {
        return 1;
        }

    // AES128
    snprintf(cmd,MAXBUF,"gpg --homedir=%s --cipher-algo \"AES\" --output=%s/AES128_%s.gpg  --force-mdc --compress-level 0 --quiet --encrypt --recipient Alpha %s/%s", dir, dir, filename_rsa_noarmour_nopassphrase, dir, filename_rsa_noarmour_nopassphrase);
    if (system(cmd))
        {
        return 1;
        }

    // AES256
    snprintf(cmd,MAXBUF,"gpg --homedir=%s --cipher-algo \"AES256\" --output=%s/AES256_%s.gpg  --force-mdc --compress-level 0 --quiet --encrypt --recipient Alpha %s/%s", dir, dir, filename_rsa_noarmour_nopassphrase, dir, filename_rsa_noarmour_nopassphrase);
    if (system(cmd))
        {
        return 1;
        }


#ifdef TODO
    snprintf(cmd,MAXBUF,"gpg --openpgp --quiet --encrypt --personal-cipher-preferences='CAST5' --armor --homedir=%s --recipient Alpha %s/%s", dir, dir, filename_rsa_armour_nopassphrase);
    if (system(cmd))
        {
        return 1;
        }
    
    snprintf(cmd,MAXBUF,"gpg --openpgp --quiet --encrypt --s2k-cipher-algo CAST5 --homedir=%s --recipient Bravo %s/%s", dir, dir, filename_rsa_noarmour_passphrase);
    if (system(cmd))
        {
        return 1;
        }

    snprintf(cmd,MAXBUF,"gpg --openpgp --quiet --encrypt --s2k-cipher-algo CAST5 --armor --homedir=%s --recipient Bravo %s/%s", dir, dir, filename_rsa_armour_passphrase);
    if (system(cmd))
        {
        return 1;
        }
#endif

    // Return success
    return 0;
    }

int clean_suite_rsa_decrypt(void)
    {
	
    reset_vars();

    return 0;
    }

static void test_rsa_decrypt(const int has_armour, const int has_passphrase, const char *filename, const char* protocol)
    {
    char encfile[MAXBUF+1];
    char* testtext;
    char *suffix= has_armour ? "asc" : "gpg";
    int fd=0;
    ops_parse_info_t *pinfo;
    int rtn=0;
    
    // open encrypted file
    snprintf(encfile,MAXBUF,"%s/%s%s%s.%s",dir,
             protocol==NULL ? "" : protocol,
             protocol==NULL ? "" : "_",
             filename,suffix);
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
    ops_parse_cb_set(pinfo,callback,NULL);

    // Set up armour/passphrase options

    if (has_armour)
        ops_reader_push_dearmour(pinfo,ops_false,ops_false,ops_false);
    current_passphrase=has_passphrase ? bravo_passphrase : nopassphrase;
    
    // Do the decryption

    ops_memory_init(mem_literal_data,0);
    rtn=ops_parse(pinfo);
    ops_print_errors(ops_parse_info_get_errors(pinfo));
    CU_ASSERT(rtn==1);

    // Tidy up
    if (has_armour)
	ops_reader_pop_dearmour(pinfo);

    close(fd);
    
    // File contents should match
    testtext=create_testtext(filename);
    CU_ASSERT(strlen(testtext)==ops_memory_get_length(mem_literal_data));
    CU_ASSERT(memcmp(ops_memory_get_data(mem_literal_data),
                     testtext,
                     ops_memory_get_length(mem_literal_data))==0);
    }

static void test_rsa_decrypt_noarmour_nopassphrase(void)
    {
    int armour=0;
    int passphrase=0;
    test_rsa_decrypt(armour,passphrase,filename_rsa_noarmour_nopassphrase,NULL);
    }

static void test_rsa_decrypt_noarmour_nopassphrase_3des(void)
    {
    CU_FAIL("3DES decryption not yet unimplemented");

    /*
    int armour=0;
    int passphrase=0;
    test_rsa_decrypt(armour,passphrase,filename_rsa_noarmour_nopassphrase,"3DES");
    */
    }

static void test_rsa_decrypt_noarmour_nopassphrase_cast5(void)
    {
    int armour=0;
    int passphrase=0;
    test_rsa_decrypt(armour,passphrase,filename_rsa_noarmour_nopassphrase,"CAST5");
    }

#ifdef TODO
static void test_rsa_decrypt_armour_nopassphrase_cast5(void)
    {
    int armour=1;
    int passphrase=0;
    test_rsa_decrypt(armour,passphrase,filename_rsa_noarmour_nopassphrase,"CAST5");
    }
#endif

static void test_rsa_decrypt_noarmour_nopassphrase_aes128(void)
    {
    int armour=0;
    int passphrase=0;
    test_rsa_decrypt(armour,passphrase,filename_rsa_noarmour_nopassphrase,"AES128");
    }

static void test_rsa_decrypt_noarmour_nopassphrase_aes256(void)
    {
    int armour=0;
    int passphrase=0;
    test_rsa_decrypt(armour,passphrase,filename_rsa_noarmour_nopassphrase,"AES256");
    }

//

#ifdef TODO
static void test_rsa_decrypt_armour_nopassphrase(void)
    {
    int armour=1;
    int passphrase=0;
    test_rsa_decrypt(armour,passphrase,filename_rsa_armour_nopassphrase,NULL);
    }

static void test_rsa_decrypt_noarmour_passphrase(void)
    {
    int armour=0;
    int passphrase=1;
    test_rsa_decrypt(armour,passphrase,filename_rsa_noarmour_passphrase,NULL);
    }

static void test_rsa_decrypt_armour_passphrase(void)
    {
    int armour=1;
    int passphrase=1;
    test_rsa_decrypt(armour,passphrase,filename_rsa_armour_passphrase,NULL);
    }
#endif

static void test_todo(void)
    {
    CU_FAIL("Test TODO: IDEA");
    CU_FAIL("Test TODO: Armoured decryption (with&without passphrase)");
    CU_FAIL("Test TODO: Decryption with multiple keys in same keyring");
    CU_FAIL("Test TODO: Decryption with multiple keys where some are not in my keyring");
    CU_FAIL("Test TODO: Decryption with multiple keys where my key is (a) first key in list; (b) last key in list; (c) in the middle of the list");
    }

CU_pSuite suite_rsa_decrypt()
{
    CU_pSuite suite = NULL;

    suite = CU_add_suite("RSA Decryption Suite", init_suite_rsa_decrypt, clean_suite_rsa_decrypt);
    if (!suite)
	    return NULL;

    // add tests to suite
    
    if (NULL == CU_add_test(suite, "Unarmoured, no passphrase (Default)", test_rsa_decrypt_noarmour_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Unarmoured, no passphrase (CAST5)", test_rsa_decrypt_noarmour_nopassphrase_cast5))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Unarmoured, no passphrase (AES128)", test_rsa_decrypt_noarmour_nopassphrase_aes128))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Unarmoured, no passphrase (AES256)", test_rsa_decrypt_noarmour_nopassphrase_aes256))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Unarmoured, no passphrase (3DES)", test_rsa_decrypt_noarmour_nopassphrase_3des))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Tests to be implemented", test_todo))
	    return NULL;
    
    return suite;
}

