#include "CUnit/Basic.h"

#include <openpgpsdk/types.h>
#include "openpgpsdk/keyring.h"
#include <openpgpsdk/armour.h>
#include "openpgpsdk/packet.h"
#include "openpgpsdk/packet-parse.h"
#include "openpgpsdk/util.h"
#include "openpgpsdk/std_print.h"

#include "tests.h"

#define MAXBUF 128
static char pub_keyring_name[MAXBUF+1];
static char keydetails[MAXBUF+1];
static ops_keyring_t pub_keyring;
static char *filename_rsa_noarmour_singlekey="rsa_noarmour_singlekey.txt";

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

#ifdef XXX
static ops_parse_cb_return_t
callback(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;
    static ops_boolean_t skipping;
    static const ops_key_data_t *encrypter;
    const ops_key_data_t *keydata=NULL;
    const ops_secret_key_t *secret;

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
		//	printf ("OPS_PTAG_CT_PK_SESSION_KEY\n");
	if(encrypter)
	    break;

	encrypter=ops_keyring_find_key_by_id(&keyring,
					     content->pk_session_key.key_id);
	if(!encrypter)
	    break;
	break;

    case OPS_PARSER_CMD_GET_SECRET_KEY:
	keydata=ops_keyring_find_key_by_id(&keyring,content->get_secret_key.pk_session_key->key_id);
	if (!keydata || !ops_key_is_secret(keydata))
	    return 0;

	//	ops_set_secret_key(content,keydata);

	// Do we need the passphrase and not have it? If so, get it
	ops_parser_content_t pc;
	char *passphrase;
	memset(&pc,'\0',sizeof pc);
	passphrase=NULL;
	pc.content.secret_key_passphrase.passphrase=&passphrase;
	pc.content.secret_key_passphrase.secret_key=&(keydata->key.skey);

	/* Ugh. Need to duplicate this macro here to get the passphrase 
	   Duplication to be removed when the callback gets moved to main code.
	   Can we make this inline code rather than a macro?
	*/
#define CB(cbinfo,t,pc)	do { (pc)->tag=(t); if((cbinfo)->cb(pc,(cbinfo)) == OPS_RELEASE_MEMORY) ops_parser_content_free(pc); } while(0)
	CB(cbinfo,OPS_PARSER_CMD_GET_SK_PASSPHRASE,&pc);
	
	/* now get the key from the data */
	secret=ops_get_secret_key_from_data(keydata);
	while(!secret)
	    {
	    /* then it must be encrypted */
	    secret=ops_decrypt_secret_key_from_data(keydata,passphrase);
	    free(passphrase);
	    }

	*content->get_secret_key.secret_key=secret;
	
	break;

    case OPS_PARSER_CMD_GET_SK_PASSPHRASE:
	/*
	  Doing this so the test can be automated.
	  Will move this into separate stacked callback later
	*/
	*(content->secret_key_passphrase.passphrase)=ops_malloc_passphrase(current_passphrase);
	return OPS_KEEP_MEMORY;
	break;

    case OPS_PTAG_CT_LITERAL_DATA_BODY:
	text=ops_mallocz(content->literal_data_body.length+1);
	memcpy(text,content->literal_data_body.data,content->literal_data_body.length);
		break;

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
	fprintf(stderr,"Unexpected packet tag=%d (0x%x)\n",content_->tag,
		content_->tag);
	assert(0);
	}

    return OPS_RELEASE_MEMORY;
    }
#endif


/* Decryption suite initialization.
 * Create temporary directory.
 * Create temporary test files.
 */

int init_suite_rsa_encrypt(void)
    {
    int fd=0;
    char cmd[MAXBUF+1];
    char *rsa_nopass="Key-Type: RSA\nKey-Usage: encrypt, sign\nName-Real: Alpha\nName-Comment: RSA, no passphrase\nName-Email: alpha@test.com\nKey-Length: 1024\n";
    char *rsa_pass="Key-Type: RSA\nKey-Usage: encrypt, sign\nName-Real: Bravo\nName-Comment: RSA, passphrase\nName-Email: bravo@test.com\nPassphrase: hello\nKey-Length: 1024\n";
    
    // Create temp directory
    if (!mktmpdir())
	return 1;

    // Create RSA test files

    create_testfile(filename_rsa_noarmour_singlekey);
    /*
    create_testfile(filename_rsa_armour_nopassphrase);
    create_testfile(filename_rsa_noarmour_passphrase);
    create_testfile(filename_rsa_armour_passphrase);
    */

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

    snprintf(cmd,MAXBUF,"gpg --quiet --gen-key --expert --homedir=%s --batch %s",dir,keydetails);
    system(cmd);

#ifdef XXX    
    // Now encrypt the test file with GPG
    snprintf(cmd,MAXBUF,"gpg --quiet --encrypt --homedir=%s --recipient Alpha %s/%s", dir, dir, filename_rsa_noarmour_nopassphrase);
    if (system(cmd))
	{
	return 1;
	}

    // Now encrypt and ascii-armour the test file with GPG
    snprintf(cmd,MAXBUF,"gpg --quiet --encrypt --armor --homedir=%s --recipient Alpha %s/%s", dir, dir, filename_rsa_armour_nopassphrase);
    if (system(cmd))
	{
	return 1;
	}
    
#endif
    
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

    snprintf(cmd,MAXBUF,"gpg --quiet --gen-key --expert --homedir=%s --batch %s",dir,keydetails);
    system(cmd);

#ifdef XXX    
    // Now encrypt the test file with GPG
    snprintf(cmd,MAXBUF,"gpg --quiet --encrypt --homedir=%s --recipient Bravo %s/%s", dir, dir, filename_rsa_noarmour_passphrase);
    if (system(cmd))
	{
	return 1;
	}

    // Now encrypt and ascii-armour the test file with GPG
    snprintf(cmd,MAXBUF,"gpg --quiet --encrypt --armor --homedir=%s --recipient Bravo %s/%s", dir, dir, filename_rsa_armour_passphrase);
    if (system(cmd))
	{
	return 1;
	}
#endif

    // Initialise OPS 
    ops_init();

    // read keyring
    snprintf(pub_keyring_name,MAXBUF,"%s/pubring.gpg", dir);
    ops_keyring_read(&pub_keyring,pub_keyring_name);

    // Return success
    return 0;
    }

int clean_suite_rsa_encrypt(void)
    {
    // char cmd[MAXBUF+1];
	
    /* Close OPS */
    
    ops_keyring_free(&pub_keyring);
    ops_finish();

    /* Remove test dir and files */
    /*
    snprintf(cmd,MAXBUF,"rm -rf %s", dir);
    if (system(cmd))
	{
	perror("Can't delete test directory ");
	return 1;
	}
   */ 
    return 0;
    }

static void test_rsa_encrypt(const int has_armour __attribute__((__unused__)), const ops_key_data_t *key __attribute__((__unused__)), const char *filename __attribute__((__unused__)))
    {
#ifdef NOTYETUSED
    char myfile[MAXBUF+1];
    char encfile[MAXBUF+1];
    char *suffix= has_armour ? "asc" : "gpg";
    int fd_in=0;
    int fd_out=0;
    ops_create_info_t *cinfo;
    //    ops_crypt_t encrypt;
    
    // open file to encrypt
    snprintf(myfile,MAXBUF,"%s/%s",dir,filename);
    fd_in=open(myfile,O_RDONLY);
    if(fd_in < 0)
	{
	perror(myfile);
	exit(2);
	}
    
    snprintf(encfile,MAXBUF,"%s/%s.%s",dir,filename,suffix);
    fd_out=open(encfile,O_WRONLY | O_CREAT | O_EXCL, 0600);
    if(fd_out < 0)
	{
	perror(encfile);
	exit(2);
	}
    
    // Set encryption writer and handling options

    cinfo=ops_create_info_new();
    ops_writer_set_fd(cinfo,fd_out); 
    // ops_parse_cb_set(pinfo,callback,NULL);

    // key in this instance is the public key of the recipient

    // setup encrypt struct
    //	unsigned char key[OPS_MAX_KEY_SIZE];
    /*
    encrypt.set_iv(&encrypt,key.iv);
    encrypt.set_key(&encrypt,??);
*/
    //    ops_crypt_any(&encrypt,key.algorithm);
    //    ops_encrypt_init(&encrypt);

    ops_writer_push_encrypt(cinfo,key);

    // Set up armour/passphrase options

    /*
    if (has_armour)
	ops_writer_push_armour(cinfo,ops_false,ops_false,ops_false);
	*/
    // current_passphrase=has_passphrase ? passphrase : nopassphrase;
    
    // Do the encryption

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
    
    // Tidy up

    close(fd_in);
    close(fd_out);

     // File contents should match
    char *text;
    char buffer[MAXBUF+1];
    create_testtext(filename,&buffer[0],MAXBUF);
    CU_ASSERT(strcmp(text,buffer)==0);
#endif
    }

void test_rsa_encrypt_noarmour_singlekey(void)
    {
    int armour=0;
    char *user_id="Alpha (RSA, no passphrase) <alpha@test.com>";
    const ops_key_data_t *pub_key=ops_keyring_find_key_by_userid(&pub_keyring, user_id);
    assert(pub_key);
    test_rsa_encrypt(armour,pub_key,filename_rsa_noarmour_singlekey);
    }

#ifdef TBD
void test_rsa_encrypt_armour(void)
    {
    int armour=1;
    test_rsa_encrypt(armour,passphrase,filename_rsa_armour_nopassphrase);
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

CU_pSuite suite_rsa_encrypt()
{
    CU_pSuite suite = NULL;

    suite = CU_add_suite("RSA Encryption Suite", init_suite_rsa_encrypt, clean_suite_rsa_encrypt);
    if (!suite)
	    return NULL;

#ifdef TBD
    // add tests to suite
    
    if (NULL == CU_add_test(suite, "Unarmoured, single key", test_rsa_encrypt_noarmour_singlekey))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Armoured, no passphrase", test_rsa_encrypt_armour_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Unarmoured, passphrase", test_rsa_encrypt_noarmour_passphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Armoured, passphrase", test_rsa_encrypt_armour_passphrase))
	    return NULL;
#endif /*TBD*/
    
    return suite;
}

