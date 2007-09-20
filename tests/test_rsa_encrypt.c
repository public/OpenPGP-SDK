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

static char *filename_rsa_noarmour_nopassphrase_singlekey="enc_rsa_noarmour_np_singlekey.txt";
static char *filename_rsa_noarmour_passphrase_singlekey="enc_rsa_noarmour_pp_singlekey.txt";
static char *filename_rsa_armour_singlekey="enc_rsa_armour_singlekey.txt";

static ops_parse_cb_return_t
callback_ops_decrypt(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
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

/* Decryption suite initialization.
 * Create temporary directory.
 * Create temporary test files.
 */

int init_suite_rsa_encrypt(void)
    {
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

int clean_suite_rsa_encrypt(void)
    {
	
    ops_finish();

    reset_vars();

    return 0;
    }

static void test_rsa_decrypt(const char *encfile, const char*testtext)
    {
    int fd=0;
    ops_parse_info_t *pinfo;
    int rtn=0;

    // open encrypted file
    fd=open(encfile,O_RDONLY);
    if(fd < 0)
	{
	perror(encfile);
	exit(2);
	}
    
    // Set decryption reader and handling options

    pinfo=ops_parse_info_new();
    ops_reader_set_fd(pinfo,fd);
    ops_parse_cb_set(pinfo,callback_ops_decrypt,NULL);

    //    current_passphrase=nopassphrase;
    
    // Do the decryption

    rtn=ops_parse(pinfo);
    CU_ASSERT(rtn==1);

    // Tidy up

    close(fd);
    
    // File contents should match
    CU_ASSERT(memcmp(literal_data,testtext,sz_literal_data)==0);
    }

static void test_rsa_encrypt(const int has_armour, const ops_key_data_t *pub_key, const char *filename)
    {
    ops_memory_t *mem_ldt;
    ops_create_info_t *cinfo_ldt;

    char cmd[MAXBUF+1];
    char myfile[MAXBUF+1];
    char encrypted_file[MAXBUF+1];
    char decrypted_file[MAXBUF+1];
    char *suffix= has_armour ? "asc" : "gpg";
    int fd_in=0;
    int fd_out=0;
    int rtn=0;
    
    // open file to encrypt
    snprintf(myfile,MAXBUF,"%s/%s",dir,filename);
    fd_in=open(myfile,O_RDONLY);
    if(fd_in < 0)
        {
        perror(myfile);
        exit(2);
        }
    
    snprintf(encrypted_file,MAXBUF,"%s/%s.%s",dir,filename,suffix);
    fd_out=open(encrypted_file,O_WRONLY | O_CREAT | O_EXCL, 0600);
    if(fd_out < 0)
        {
        perror(encrypted_file);
        exit(2);
        }
    
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

    //    ops_writer_push_encrypt(cinfo,key);

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
#ifdef USING_PUSH
	    ops_write(buf,n,cinfo);
#else
        // create a simple literal data packet as the encrypted payload
        ops_setup_memory_write(&cinfo_ldt,&mem_ldt,n);
        ops_write_literal_data((unsigned char *)buf, n,
                           OPS_LDT_BINARY, cinfo_ldt);
#endif
    }

    // write to file

    // Set encryption writer and handling options

    ops_create_info_t *cinfo;
    cinfo=ops_create_info_new();
    ops_writer_set_fd(cinfo,fd_out); 

    // Create and write encrypted PK session key

    //    char *user_id="Alpha (RSA, no passphrase) <alpha@test.com>";
    //    const ops_key_data_t *pub_key=ops_keyring_find_key_by_userid(&pub_keyring, user_id);
    //    ops_print_public_key_verbose(pub_key);

    ops_pk_session_key_t* encrypted_pk_session_key;
    encrypted_pk_session_key=ops_create_pk_session_key(pub_key);
    ops_write_pk_session_key(cinfo,encrypted_pk_session_key);

    ops_crypt_t encrypt;
    ops_crypt_any(&encrypt, encrypted_pk_session_key->symmetric_algorithm);
    unsigned char *iv=NULL;
    iv=ops_mallocz(encrypt.blocksize);
    encrypt.set_iv(&encrypt, iv);
    //key=ops_mallocz(encrypt.keysize); 
    encrypt.set_key(&encrypt, &encrypted_pk_session_key->key[0]);
    ops_encrypt_init(&encrypt);

    /*
     * write out the encrypted packet
     */

    ops_write_se_ip_data( ops_memory_get_data(mem_ldt),
                          ops_memory_get_length(mem_ldt),
                          &encrypt, cinfo);

    
    // Tidy up

    close(fd_in);
    close(fd_out);

     // File contents should match - check with OPS
    char buffer[MAXBUF+1];
    create_testtext(filename,&buffer[0],MAXBUF);
    test_rsa_decrypt(encrypted_file,buffer);

    // File contents should match - check with GPG

    char pp[MAXBUF];
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

void test_rsa_encrypt_noarmour_nopassphrase_singlekey(void)
    {
    int armour=0;
    test_rsa_encrypt(armour,alpha_pub_keydata,filename_rsa_noarmour_nopassphrase_singlekey);
    }

void test_rsa_encrypt_noarmour_passphrase_singlekey(void)
    {
    int armour=0;
    test_rsa_encrypt(armour,bravo_pub_keydata,filename_rsa_noarmour_passphrase_singlekey);  
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

    // add tests to suite
    
    if (NULL == CU_add_test(suite, "Unarmoured, single key, no passphrase", test_rsa_encrypt_noarmour_nopassphrase_singlekey))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Unarmoured, single key, passphrase", test_rsa_encrypt_noarmour_passphrase_singlekey))
	    return NULL;
    
#ifdef TBD
    if (NULL == CU_add_test(suite, "Armoured, single key", test_rsa_encrypt_armour_singlekey))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Armoured, passphrase", test_rsa_encrypt_armour_passphrase))
	    return NULL;
#endif /*TBD*/
    
    return suite;
}

