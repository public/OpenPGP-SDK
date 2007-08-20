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

//static ops_keyring_t keyring;
static char *filename_rsa_noarmour_nopassphrase="dec_rsa_noarmour_nopassphrase.txt";
static char *filename_rsa_armour_nopassphrase="dec_rsa_armour_nopassphrase.txt";
static char *filename_rsa_noarmour_passphrase="dec_rsa_noarmour_passphrase.txt";
static char *filename_rsa_armour_passphrase="dec_rsa_armour_passphrase.txt";
static char *nopassphrase="";
static char *passphrase="hello";
static char *current_passphrase=NULL;

//static char* text;

/*
static int create_testfile(const char *name)
    {
    char filename[MAXBUF+1];
    char buffer[MAXBUF+1];

    int fd=0;
    snprintf(filename,MAXBUF,"%s/%s",dir,name);
    if ((fd=open(filename,O_WRONLY| O_CREAT | O_EXCL, 0600))<0)
	return 0;

    create_testtext(name,&buffer[0],MAXBUF);
    write(fd,buffer,strlen(buffer));
    close(fd);
    return 1;
    }
*/

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
        /*
	text=ops_mallocz(content->literal_data_body.length+1);
	memcpy(text,content->literal_data_body.data,content->literal_data_body.length);
        */
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

    // Restrict list of algorithms used
   
    //    snprintf(cmd,MAXBUF,"gpg --homedir=%s --default-preference-list \"CAST5\"", dir);
    //    if (system(cmd))
    //        return -1;

    // Now encrypt the test files with GPG
    // Note:: To make it do SE_IP packets, do NOT use --openpgp and DO use --force-mdc
    snprintf(cmd,MAXBUF,"gpg --homedir=%s --cipher-algo \"CAST5\" --force-mdc --compress-level 0 --quiet --encrypt --recipient Alpha %s/%s", dir, dir, filename_rsa_noarmour_nopassphrase);
    if (system(cmd))
        {
        return 1;
        }

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

#ifdef XXX
    int fd=0;
    char *rsa_nopass="Key-Type: RSA\nKey-Usage: encrypt, sign\nName-Real: Alpha\nName-Comment: RSA, no passphrase\nName-Email: alpha@test.com\nKey-Length: 1024\n";
    char *rsa_pass="Key-Type: RSA\nKey-Usage: encrypt, sign\nName-Real: Bravo\nName-Comment: RSA, passphrase\nName-Email: bravo@test.com\nPassphrase: hello\nKey-Length: 1024\n";
    
    // Create temp directory
    if (!mktmpdir())
	return 1;

    /*
     * Create a RSA keypair with no passphrase
     */

    snprintf(keydetails,MAXBUF,"%s/%s",dir,"keydetails.alpha");

    if ((fd=open(keydetails,O_WRONLY | O_CREAT | O_EXCL, 0600))<0)
	{
	fprintf(stderr,"Can't create key details\n");
	return 1;
	}

    write(fd,rsa_nopass,strlen(rsa_nopass));
    close(fd);

    snprintf(cmd,MAXBUF,"gpg --openpgp --quiet --gen-key --expert --homedir=%s --batch %s",dir,keydetails);
    system(cmd);

    /*
     * Create a RSA keypair with passphrase
     */

    snprintf(keydetails,MAXBUF,"%s/%s",dir,"keydetails.bravo");
    if ((fd=open(keydetails,O_WRONLY | O_CREAT | O_EXCL, 0600))<0)
	{
	fprintf(stderr,"Can't create key details\n");
	return 1;
	}

    write(fd,rsa_pass,strlen(rsa_pass));
    close(fd);

    snprintf(cmd,MAXBUF,"gpg --openpgp --quiet --gen-key --expert --homedir=%s --batch %s",dir,keydetails);
    system(cmd);


    // Initialise OPS 
    ops_init();

    // read keyring
    snprintf(secring,MAXBUF,"%s/secring.gpg", dir);
    ops_keyring_read(&keyring,secring);
#endif

    // Return success
    return 0;
    }

int clean_suite_rsa_decrypt(void)
    {
	
#ifdef XXX
    char cmd[MAXBUF+1];
    /* Close OPS */
    
    ops_keyring_free(&keyring);
    ops_finish();

    /* Remove test dir and files */
    snprintf(cmd,MAXBUF,"rm -rf %s", dir);
    if (system(cmd))
	{
	perror("Can't delete test directory ");
	return 1;
	}
#endif
    
    reset_vars();

    return 0;
    }

static void test_rsa_decrypt(const int has_armour, const int has_passphrase, const char *filename)
    {
    char encfile[MAXBUF+1];
    char testtext[MAXBUF+1];
    char *suffix= has_armour ? "asc" : "gpg";
    int fd=0;
    ops_parse_info_t *pinfo;
    
    // open encrypted file
    snprintf(encfile,MAXBUF,"%s/%s.%s",dir,filename,suffix);
    fd=open(encfile,O_RDONLY);
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
    current_passphrase=has_passphrase ? passphrase : nopassphrase;
    
    // Do the decryption

    ops_parse(pinfo);

    // Tidy up
    if (has_armour)
	ops_reader_pop_dearmour(pinfo);

    close(fd);
    
    // File contents should match
    create_testtext(filename,&testtext[0],MAXBUF);
    CU_ASSERT(memcmp(literal_data,testtext,sz_literal_data)==0);
    }

void test_rsa_decrypt_noarmour_nopassphrase(void)
    {
    int armour=0;
    int passphrase=0;
    test_rsa_decrypt(armour,passphrase,filename_rsa_noarmour_nopassphrase);
    }

void test_rsa_decrypt_armour_nopassphrase(void)
    {
    int armour=1;
    int passphrase=0;
    test_rsa_decrypt(armour,passphrase,filename_rsa_armour_nopassphrase);
    }

void test_rsa_decrypt_noarmour_passphrase(void)
    {
    int armour=0;
    int passphrase=1;
    test_rsa_decrypt(armour,passphrase,filename_rsa_noarmour_passphrase);
    }

void test_rsa_decrypt_armour_passphrase(void)
    {
    int armour=1;
    int passphrase=1;
    test_rsa_decrypt(armour,passphrase,filename_rsa_armour_passphrase);
    }

/*
int main()
    {
    CU_pSuite suite_rsa_decrypt = NULL;
    CU_pSuite suite_rsa_encrypt = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
	return CU_get_error();
*/

CU_pSuite suite_rsa_decrypt()
{
    CU_pSuite suite = NULL;

    suite = CU_add_suite("RSA Decryption Suite", init_suite_rsa_decrypt, clean_suite_rsa_decrypt);
    if (!suite)
	    return NULL;

    // add tests to suite
    
    if (NULL == CU_add_test(suite, "Unarmoured, no passphrase", test_rsa_decrypt_noarmour_nopassphrase))
	    return NULL;
    
#ifdef TODO
    if (NULL == CU_add_test(suite, "Armoured, no passphrase", test_rsa_decrypt_armour_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Unarmoured, passphrase", test_rsa_decrypt_noarmour_passphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Armoured, passphrase", test_rsa_decrypt_armour_passphrase))
	    return NULL;
#endif    
    return suite;
}

