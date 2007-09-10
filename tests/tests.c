#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "CUnit/Basic.h"
#include "openpgpsdk/readerwriter.h"
// \todo remove the need for this
#include "../src/advanced/parse_local.h"

#include "tests.h"

char dir[MAXBUF+1];
ops_keyring_t pub_keyring;
ops_keyring_t sec_keyring;
static char* no_passphrase="";
unsigned char* literal_data=NULL;
size_t sz_literal_data=0;
char *alpha_user_id="Alpha (RSA, no passphrase) <alpha@test.com>";
char *bravo_user_id="Bravo (RSA, passphrase) <bravo@test.com>";
char *alpha_name="Alpha";
char *bravo_name="Bravo";
const ops_public_key_t *alpha_pkey;
const ops_secret_key_t *alpha_skey;
const ops_public_key_t *bravo_pkey;
const ops_secret_key_t *bravo_skey;

const ops_key_data_t *decrypter=NULL;

void setup_test_keys()
    {
    const ops_key_data_t* alpha_keydata;
    const ops_key_data_t* bravo_keydata;
    char keydetails[MAXBUF+1];
    char keyring_name[MAXBUF+1];
    int fd=0;
    char cmd[MAXBUF+1];

    char *rsa_nopass="Key-Type: RSA\nKey-Usage: encrypt, sign\nName-Real: Alpha\nName-Comment: RSA, no passphrase\nName-Email: alpha@test.com\nKey-Length: 1024\n";
    char *rsa_pass="Key-Type: RSA\nKey-Usage: encrypt, sign\nName-Real: Bravo\nName-Comment: RSA, passphrase\nName-Email: bravo@test.com\nPassphrase: hello\nKey-Length: 1024\n";

    // Create temp directory
    if (!mktmpdir())
        return;

    /*
     * Create a RSA keypair with no passphrase
     */

    snprintf(keydetails,MAXBUF,"%s/%s",dir,"keydetails.alpha");

    if ((fd=open(keydetails,O_WRONLY | O_CREAT | O_EXCL, 0600))<0)
        {
        fprintf(stderr,"Can't create Alpha key details\n");
        return;
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
        fprintf(stderr,"Can't create Bravo key details\n");
        return;
        }

    write(fd,rsa_pass,strlen(rsa_pass));
    close(fd);

    snprintf(cmd,MAXBUF,"gpg --openpgp --quiet --gen-key --expert --homedir=%s --batch %s",dir,keydetails);
    system(cmd);
    
    /*
     * read keyrings
     */

    snprintf(keyring_name,MAXBUF,"%s/pubring.gpg", dir);
    ops_keyring_read(&pub_keyring,keyring_name);

    snprintf(keyring_name,MAXBUF,"%s/secring.gpg", dir);
    ops_keyring_read(&sec_keyring,keyring_name);

    /*
     * set up key pointers
     */

    assert(pub_keyring.nkeys);
    alpha_keydata=ops_keyring_find_key_by_userid(&sec_keyring, alpha_user_id);
    bravo_keydata=ops_keyring_find_key_by_userid(&sec_keyring, bravo_user_id);

    alpha_pkey=ops_get_public_key_from_data(alpha_keydata);
    alpha_skey=ops_get_secret_key_from_data(alpha_keydata);
    bravo_pkey=ops_get_public_key_from_data(bravo_keydata);
    bravo_skey=ops_get_secret_key_from_data(bravo_keydata);

    assert(alpha_pkey);
    assert(alpha_skey);
    assert(bravo_pkey);
    //    assert(bravo_skey); not yet set because of passphrase
    }

static void cleanup()
    {
    char cmd[MAXBUF];

    return;

    /* Remove test dir and files */
    snprintf(cmd,MAXBUF,"rm -rf %s", dir);
    if (system(cmd))
        {
        perror("Can't delete test directory ");
        return;
        }
    }

int main()
    {

    setup_test_keys();

    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    if (NULL == suite_crypto())
        {
        CU_cleanup_registry();
        return CU_get_error();
        }

    /*
    if (NULL == suite_crypt_mpi())
        {
        CU_cleanup_registry();
        return CU_get_error();
        }
    */

    if (NULL == suite_packet_types())
        {
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_rsa_encrypt()) 
        {
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_rsa_decrypt()) 
        {
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_rsa_signature()) 
        {
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_rsa_verify()) 
        {
        CU_cleanup_registry();
        return CU_get_error();
        }

    // Run tests
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();

    cleanup();

    return CU_get_error();
    }

int mktmpdir (void)
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
	    fprintf (stderr,"Couldn't open dir: errno=%d\n", errno);
	    perror(NULL);
	    }
	}
    return 0;
    }

void create_testtext(const char *text, char *buf, const int maxlen)
    {
    buf[maxlen]='\0';
    snprintf(buf,maxlen,"%s : Test Text\n", text);
    }

void create_testdata(const char *text, unsigned char *buf, const int maxlen)
    {
    char *preamble=" : Test Data :";
    int i=0;

    snprintf((char *)buf,maxlen,"%s%s", text, preamble);

    for (i=strlen(text)+strlen(preamble); i<maxlen; i++)
        {
        buf[i]=(random() & 0xFF);
        }
    }

void create_testfile(const char *name)
    {
    char filename[MAXBUF+1];
    char buffer[MAXBUF+1];

    int fd=0;
    snprintf(filename,MAXBUF,"%s/%s",dir,name);
    if ((fd=open(filename,O_WRONLY| O_CREAT | O_EXCL, 0600))<0)
	return;

    create_testtext(name,&buffer[0],MAXBUF);
    write(fd,buffer,strlen(buffer));
    close(fd);
    }

ops_parse_cb_return_t
callback_general(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;
    
    OPS_USED(cbinfo);
    
    //    ops_print_packet(content_);
    
    switch(content_->tag)
        {
    case OPS_PARSER_PTAG:
        // ignore
        break;
        
    case OPS_PARSER_ERROR:
        printf("parse error: %s\n",content->error.error);
        break;
        
    case OPS_PARSER_ERRCODE:
        printf("parse error: %s\n",
               ops_errcode(content->errcode.errcode));
        break;
        
    default:
        fprintf(stderr,"Unexpected packet tag=%d (0x%x)\n",content_->tag,
                content_->tag);
        assert(0);
        }
    
    return OPS_RELEASE_MEMORY;
    }

ops_parse_cb_return_t
callback_cmd_get_secret_key(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;
    const ops_key_data_t *keydata=NULL;
    const ops_secret_key_t *secret;

    OPS_USED(cbinfo);

//    ops_print_packet(content_);

    switch(content_->tag)
	{
    case OPS_PARSER_CMD_GET_SECRET_KEY:
        keydata=ops_keyring_find_key_by_id(&sec_keyring,content->get_secret_key.pk_session_key->key_id);
        if (!keydata || !ops_key_is_secret(keydata))
            return 0;

        // Do we need the passphrase and not have it? If so, get it
        ops_parser_content_t pc;
        char *passphrase;
        memset(&pc,'\0',sizeof pc);
        passphrase=NULL;
        pc.content.secret_key_passphrase.passphrase=&passphrase;
        pc.content.secret_key_passphrase.secret_key=ops_get_secret_key_from_data(keydata);

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

    default:
        return callback_general(content_,cbinfo);
	}
    
    return OPS_RELEASE_MEMORY;
    }

ops_parse_cb_return_t
callback_cmd_get_secret_key_passphrase(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;
    /*
    static const ops_key_data_t *decrypt_key;
    const ops_key_data_t *keydata=NULL;
    const ops_secret_key_t *secret;
    */

    OPS_USED(cbinfo);

//    ops_print_packet(content_);

    switch(content_->tag)
        {
    case OPS_PARSER_CMD_GET_SK_PASSPHRASE:
        /*
          Doing this so the test can be automated.
        */
        *(content->secret_key_passphrase.passphrase)=ops_malloc_passphrase(no_passphrase);
        return OPS_KEEP_MEMORY;
        break;
        
    default:
        return callback_general(content_,cbinfo);
	}
    
    return OPS_RELEASE_MEMORY;
    }

ops_parse_cb_return_t
callback_literal_data(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;

    OPS_USED(cbinfo);

    //    ops_print_packet(content_);

    // Read data from packet into static buffer
    switch(content_->tag)
        {
    case OPS_PTAG_CT_LITERAL_DATA_BODY:
        sz_literal_data=content->literal_data_body.length;
        literal_data=ops_mallocz(sz_literal_data+1);
        memcpy(literal_data,content->literal_data_body.data,sz_literal_data);
        break;

    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
        // ignore
        break;

    default:
        return callback_general(content_,cbinfo);
        }

    return OPS_RELEASE_MEMORY;
    }
 
// move definition to better location
ops_parse_cb_return_t
validate_cb(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);

ops_parse_cb_return_t
callback_signature(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    //    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;

    OPS_USED(cbinfo);

    //    ops_print_packet(content_);

    switch(content_->tag)
        {
    case OPS_PTAG_CT_ONE_PASS_SIGNATURE:
    case OPS_PTAG_CT_SIGNATURE_HEADER:
    case OPS_PTAG_CT_SIGNATURE_FOOTER:
        return validate_cb(content_,cbinfo);
        break;

    default:
        return callback_general(content_,cbinfo);
        }

    return OPS_RELEASE_MEMORY;
    }
 
ops_parse_cb_return_t
callback_pk_session_key(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;
    
    OPS_USED(cbinfo);

    //    ops_print_packet(content_);
    
    // Read data from packet into static buffer
    switch(content_->tag)
        {
    case OPS_PTAG_CT_PK_SESSION_KEY:
		//	printf ("OPS_PTAG_CT_PK_SESSION_KEY\n");
        if(decrypter)
            break;

        decrypter=ops_keyring_find_key_by_id(&sec_keyring,
                                             content->pk_session_key.key_id);
        if(!decrypter)
            break;
        break;

    default:
        return callback_general(content_,cbinfo);
        }

    return OPS_RELEASE_MEMORY;
    }

void reset_vars()
    {
    if (literal_data)
        {
        free (literal_data);
        literal_data=NULL;
        sz_literal_data=0;
        }
    if (decrypter)
        {
        //        free (decrypter);
        decrypter=NULL;
        }
    }

int file_compare(char* file1, char* file2)
    {
    FILE *fp1=NULL;
    FILE *fp2=NULL;
    char ch1, ch2;
    int err=0;

    // open files
    if ((fp1=fopen(file1,"rb"))==NULL)
        {
        fprintf(stderr,"file_compare: cannot open file %s\n",file1);
        return -1;
        }
    if ((fp2=fopen(file2,"rb"))==NULL)
        {
        fprintf(stderr,"file_compare: cannot open file %s\n",file2);
        fclose(fp1);
        return -1;
        }

    while(!feof(fp1))
        {
        ch1 = fgetc(fp1);
        if (ferror(fp1))
            {
            fprintf(stderr,"file_compare: error reading from file %s\n",file1);
            err = -1;
            break;
            }
        ch2 = fgetc(fp2);
        if (ferror(fp2))
            {
            fprintf(stderr,"file_compare: error reading from file %s\n",file2);
            err = -1;
            break;
            }
        if (ch1 != ch2)
            {
            printf("Files %s and %s differ\n",file1,file2);
            err = 1;
            break;
            }
        }
    fclose(fp1);
    fclose(fp2);
    return err;
    }
