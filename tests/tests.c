#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "CUnit/Basic.h"

#include "openpgpsdk/keyring.h"
#include "openpgpsdk/packet.h"
#include "openpgpsdk/packet-parse.h"
#include "openpgpsdk/util.h"
#include "openpgpsdk/std_print.h"

#define MAXBUF 128
static char dir[MAXBUF+1];
static char file[MAXBUF+1];
static char keydetails[MAXBUF+1];
static ops_keyring_t keyring;
static char* testtxt="Hello World\n";
static char* text;

static ops_parse_cb_return_t
callback(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;
    static ops_boolean_t skipping;
    static const ops_key_data_t *decrypter;
    const ops_key_data_t *key=NULL;

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
	printf ("OPS_PTAG_CT_PK_SESSION_KEY\n");
	if(decrypter)
	    break;

	decrypter=ops_keyring_find_key_by_id(&keyring,
					     content->pk_session_key.key_id);
	if(!decrypter)
	    break;
	break;

    case OPS_PARSER_CMD_GET_SECRET_KEY:
	key=ops_keyring_find_key_by_id(&keyring,content->get_secret_key.pk_session_key->key_id);
	if (!key || !ops_key_is_secret(key))
	    return 0;

	ops_set_secret_key(content,key);

	break;

    case OPS_PTAG_CT_LITERAL_DATA_BODY:
	text=ops_mallocz(content->literal_data_body.length+1);
	memcpy(text,content->literal_data_body.data,content->literal_data_body.length);
		break;

    case OPS_PARSER_PTAG:
    case OPS_PTAG_CT_ARMOUR_HEADER:
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

static int mktmpdir (void)
    {
    int limit=10; // don't try indefinitely
    long int rnd=0;
    while (limit--) 
	{
	rnd=random();
	snprintf(dir,MAXBUF,"./testdir.%ld",rnd);

	// Try to create directory
	if (!mkdir(dir,0700))
	    {
	    // success
	    return 1;
	    }
	else
	    {
	    printf ("Couldn't open dir: errno=%d\n", errno);
	    perror(NULL);
	    }
	}
    return 0;
    }

/* Decryption suite initialization.
 * Create temporary directory.
 * Create temporary test files.
 */

int init_suite_decrypt(void)
    {
    char *textfile="testfile.txt";
    int fd=0;
    
    // Create temp directory
    if (!mktmpdir())
	return 1;

    printf("creating new file\n");
    // Create a new unencrypted test file
    snprintf(file,MAXBUF,"%s/%s",dir,textfile);

    if ((fd=open(file,O_WRONLY| O_CREAT | O_EXCL, 0600))<0)
	return 1;
    write(fd,testtxt,strlen(testtxt));
    close(fd);

    // create new keyrings in that directory
    // and a new RSA keypair with no passphrase

    snprintf(keydetails,MAXBUF,"%s/%s",dir,"keydetails");
    if ((fd=open(keydetails,O_WRONLY | O_CREAT | O_EXCL, 0600))<0)
	{
	printf("Can't create key details\n");
	return 1;
	}

    char *rsa_nopass="Key-Type: RSA\nKey-Usage: encrypt, sign\nName-Real: Alpha\nName-Comment: RSA, no passphrase\nName-Email: alpha@test.com\nKey-Length: 1024\n";
    write(fd,rsa_nopass,strlen(rsa_nopass));
    close(fd);

    char cmd[MAXBUF+1];
    snprintf(cmd,MAXBUF,"gpg --gen-key --expert --homedir=%s --batch %s > /dev/null",dir,keydetails);
    //printf("cmd: %s\n", cmd);
    system(cmd);

    // Now encrypt the test file with GPG
    snprintf(cmd,MAXBUF,"gpg --encrypt --homedir=%s --recipient Alpha %s > /dev/null", dir, file);
    if (system(cmd))
	{
	return 1;
	}

    // Return success
    return 0;
    }

int clean_suite_decrypt(void)
    {
    char cmd[MAXBUF+1];
	
    snprintf(cmd,MAXBUF,"rm -rf %s", dir);
    if (system(cmd))
	{
	perror("Can't delete test directory ");
	return 1;
	}

    return 0;
    }

void test1(void)
    {
    char secring[MAXBUF+1];
    char encfile[MAXBUF+1];
    int fd=0;
    ops_parse_info_t *pinfo;

    snprintf(secring,MAXBUF,"%s/secring.gpg", dir);
    snprintf(encfile,MAXBUF,"%s.gpg", file);

    // read keyring
    ops_init();
    ops_keyring_read(&keyring,secring);

    // read encrypted file
    fd=open(encfile,O_RDONLY);
    if(fd < 0)
	{
	perror(encfile);
	exit(2);
	}

    // Now do file
    pinfo=ops_parse_info_new();
    ops_reader_set_fd(pinfo,fd);
    ops_parse_cb_set(pinfo,callback,NULL);

    ops_parse(pinfo);

    ops_keyring_free(&keyring);
    ops_finish();

    // File contents should match
    CU_ASSERT(strcmp(text,testtxt)==0);
    }

int main()
    {
    CU_pSuite pSuite = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
	return CU_get_error();

    pSuite = CU_add_suite("Decrypt Suite", init_suite_decrypt, clean_suite_decrypt);
    if (NULL == pSuite) 
	{
	CU_cleanup_registry();
	return CU_get_error();
	}

    // add tests to suite

    if (NULL == CU_add_test(pSuite, "test 1", test1))
	{
	CU_cleanup_registry();
	return CU_get_error();
	}

    // Run tests
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
    }

