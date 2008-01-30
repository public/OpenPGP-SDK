#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <sys/stat.h>

#include "CUnit/Basic.h"
#include "openpgpsdk/readerwriter.h"
// \todo remove the need for this
#include "../src/advanced/parse_local.h"

#include "tests.h"

char dir[MAXBUF+1];
char gpgcmd[MAXBUF+1];
ops_keyring_t pub_keyring;
ops_keyring_t sec_keyring;
static char* no_passphrase="";
ops_memory_t* mem_literal_data=NULL;

char *alpha_user_id="Alpha (RSA, no passphrase) <alpha@test.com>";
char *alpha_name="Alpha";
const ops_public_key_t *alpha_pkey;
const ops_secret_key_t *alpha_skey;
const ops_key_data_t *alpha_pub_keydata;
const ops_key_data_t *alpha_sec_keydata;
char* alpha_passphrase="";

char *bravo_user_id="Bravo (RSA, passphrase) <bravo@test.com>";
char *bravo_name="Bravo";
const ops_public_key_t *bravo_pkey;
const ops_secret_key_t *bravo_skey;
const ops_key_data_t *bravo_pub_keydata;
const ops_key_data_t *bravo_sec_keydata;
char* bravo_passphrase="hello";

const ops_key_data_t *decrypter=NULL;

static void setup_test_keys();

void setup()
    {
    // Create temp directory
    if (!mktmpdir())
        return;

    assert(strlen(dir));
    snprintf(gpgcmd,MAXBUF,"gpg --quiet --no-tty --homedir=%s --openpgp",dir);

    setup_test_keys();
    }

static void setup_test_keys()
    {
    char keydetails[MAXBUF+1];
    char keyring_name[MAXBUF+1];
    int fd=0;
    char cmd[MAXBUF+1];

    char *rsa_nopass="Key-Type: RSA\nKey-Usage: encrypt, sign\nName-Real: Alpha\nName-Comment: RSA, no passphrase\nName-Email: alpha@test.com\nKey-Length: 1024\n";
    char *rsa_pass="Key-Type: RSA\nKey-Usage: encrypt, sign\nName-Real: Bravo\nName-Comment: RSA, passphrase\nName-Email: bravo@test.com\nPassphrase: hello\nKey-Length: 1024\n";

    /*
     * Create a RSA keypair with no passphrase
     */

    snprintf(keydetails,MAXBUF,"%s/%s",dir,"keydetails.alpha");

#ifdef WIN32
    if ((fd=open(keydetails,O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600))<0)
#else
    if ((fd=open(keydetails,O_WRONLY | O_CREAT | O_EXCL, 0600))<0)
#endif
        {
        fprintf(stderr,"Can't create Alpha key details\n");
        return;
        }

    write(fd,rsa_nopass,strlen(rsa_nopass));
    close(fd);

    snprintf(cmd,MAXBUF,"%s --openpgp --gen-key --s2k-cipher-algo \"AES\" --expert --batch %s",gpgcmd,keydetails);
    system(cmd);

    /*
     * Create a RSA keypair with passphrase
     */

    snprintf(keydetails,MAXBUF,"%s/%s",dir,"keydetails.bravo");

#ifdef WIN32
    if ((fd=open(keydetails,O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600))<0)
#else
    if ((fd=open(keydetails,O_WRONLY | O_CREAT | O_EXCL, 0600))<0)
#endif
        {
        fprintf(stderr,"Can't create Bravo key details\n");
        return;
        }

    write(fd,rsa_pass,strlen(rsa_pass));
    close(fd);

    snprintf(cmd,MAXBUF,"%s --openpgp --gen-key --s2k-cipher-algo \"AES\" --expert --batch %s",gpgcmd,keydetails);
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

    alpha_pub_keydata=ops_keyring_find_key_by_userid(&pub_keyring, alpha_user_id);
    bravo_pub_keydata=ops_keyring_find_key_by_userid(&pub_keyring, bravo_user_id);
    assert(alpha_pub_keydata);
    assert(bravo_pub_keydata);

    alpha_sec_keydata=ops_keyring_find_key_by_userid(&sec_keyring, alpha_user_id);
    bravo_sec_keydata=ops_keyring_find_key_by_userid(&sec_keyring, bravo_user_id);
    assert(alpha_sec_keydata);
    assert(bravo_sec_keydata);

    alpha_pkey=ops_get_public_key_from_data(alpha_pub_keydata);
    alpha_skey=ops_get_secret_key_from_data(alpha_sec_keydata);
    bravo_pkey=ops_get_public_key_from_data(bravo_pub_keydata);
    bravo_skey=ops_decrypt_secret_key_from_data(bravo_sec_keydata,bravo_passphrase);

    assert(alpha_pkey);
    assert(alpha_skey);
    assert(bravo_pkey);
    assert(bravo_skey); //not yet set because of passphrase
    }

void cleanup()
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

int mktmpdir (void)
    {
    int limit=10; // don't try indefinitely
    long int rnd=0;

#ifdef WIN32
    srand( (unsigned)time( NULL ) );
#endif
    while (limit--) 
        {
        rnd=random();
        snprintf(dir,MAXBUF,"./testdir.%ld",rnd);
        
        // Try to create directory
#ifndef WIN32
        if (!mkdir(dir,0700))
#else
    	if (!_mkdir(dir))
#endif
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
    fprintf(stderr,"Too many temp dirs: please delete them\n");
    exit(1);
    }

char* create_testtext(const char *text)
    {
    const unsigned int repeats=1;
    unsigned int i=0;

    const unsigned int maxbuf=1024;
    char buf[maxbuf+1];
    unsigned int sz_one=0;
    unsigned int sz_big=0;
    char* bigbuf=NULL; 

    buf[maxbuf]='\0';
    snprintf(buf,maxbuf,"%s : Test Text\n", text);

    sz_one=strlen(buf);
    sz_big=sz_one*repeats+1;

    bigbuf=ops_mallocz(sz_big); 

   for (i=0; i<repeats; i++)
        {
        char* ptr=bigbuf+ (i*(sz_one-1));
        snprintf(ptr,sz_one,buf);
        }

   return bigbuf;
    }

void create_testdata(const char *text, unsigned char *buf, const int maxlen)
    {
    char *preamble=" : Test Data :";
    int i=0;

    snprintf((char *)buf,maxlen,"%s%s", text, preamble);

#ifdef WIN32
    srand( (unsigned)time( NULL ) );
#endif
    for (i=strlen(text)+strlen(preamble); i<maxlen; i++)
        {
        buf[i]=(random() & 0xFF);
        }
    }

void create_testfile(const char *name)
    {
    char filename[MAXBUF+1];
    char* testtext=NULL;

    int fd=0;
    snprintf(filename,MAXBUF,"%s/%s",dir,name);
#ifdef WIN32
    if ((fd=open(filename,O_WRONLY| O_CREAT | O_EXCL | O_BINARY, 0600))<0)
#else
    if ((fd=open(filename,O_WRONLY| O_CREAT | O_EXCL, 0600))<0)
#endif
	return;

    testtext=create_testtext(name);
    write(fd,testtext,strlen(testtext));
    close(fd);
    free(testtext);
    }

ops_parse_cb_return_t
callback_general(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    int debug=0;

    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;
    
    OPS_USED(cbinfo);
    
    //    ops_print_packet(content_);
    
    switch(content_->tag)
        {
    case OPS_PARSER_PTAG:
        // ignore
        break;
        
    case OPS_PARSER_PACKET_END:
        // print raw packet

        if (debug)
            {
            unsigned i=0;
            fprintf(stderr,"***\n***Raw Packet:\n");
            for (i=0; i<content_->content.packet.length; i++)
                {
                fprintf(stderr,"0x%02x ", content_->content.packet.raw[i]);
                if (!((i+1) % 16))
                    fprintf(stderr,"\n");
                else if (!((i+1) % 8))
                    fprintf(stderr,"  ");
                }
            fprintf(stderr,"\n");
            }
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
    char *passphrase=NULL;

    OPS_USED(cbinfo);

//    ops_print_packet(content_);

    switch(content_->tag)
	{
    case OPS_PARSER_CMD_GET_SECRET_KEY:
        keydata=ops_keyring_find_key_by_id(&sec_keyring,content->get_secret_key.pk_session_key->key_id);
        if (!keydata || !ops_key_is_secret(keydata))
            return 0;

        // Do we need the passphrase and not have it? If so, get it
        passphrase=NULL;

        /*
         * Hard-coded to allow automated test
         */
        if (keydata==alpha_sec_keydata)
            passphrase=alpha_passphrase;
        else if (keydata==bravo_sec_keydata)
            passphrase=bravo_passphrase;
        else
            assert(0);

        /* now get the key from the data */
        secret=ops_get_secret_key_from_data(keydata);
        while(!secret)
            {
            /* then it must be encrypted */
            secret=ops_decrypt_secret_key_from_data(keydata,passphrase);
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
        ops_memory_add(mem_literal_data,
                       content->literal_data_body.data,
                       content->literal_data_body.length);
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
validate_key_cb(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);
ops_parse_cb_return_t
validate_data_cb(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);

ops_parse_cb_return_t
callback_data_signature(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    //    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;

    OPS_USED(cbinfo);

    //    ops_print_packet(content_);

    switch(content_->tag)
        {
    case OPS_PTAG_CT_SIGNED_CLEARTEXT_HEADER:
    case OPS_PTAG_CT_SIGNED_CLEARTEXT_BODY:
    case OPS_PTAG_CT_SIGNED_CLEARTEXT_TRAILER:

    case OPS_PTAG_CT_ONE_PASS_SIGNATURE:
    case OPS_PTAG_CT_SIGNATURE_HEADER:
    case OPS_PTAG_CT_SIGNATURE_FOOTER:

    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
    case OPS_PTAG_CT_LITERAL_DATA_BODY:

    case OPS_PTAG_CT_SIGNATURE:
        return validate_data_cb(content_,cbinfo);
        break;

    default:
        return callback_general(content_,cbinfo);
        }

    return OPS_RELEASE_MEMORY;
    }
 
ops_parse_cb_return_t
callback_verify(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    /*
    int debug=0;

    if (debug)
        { ops_print_packet(content_); }
    */
    switch(content_->tag)
        {
    case OPS_PTAG_RAW_SS:
    case OPS_PTAG_SS_CREATION_TIME:
    case OPS_PTAG_SS_ISSUER_KEY_ID:
        // \todo should free memory?
        return OPS_KEEP_MEMORY;
        
    case OPS_PTAG_CT_ONE_PASS_SIGNATURE:
    case OPS_PTAG_CT_ARMOUR_HEADER:
    case OPS_PTAG_CT_ARMOUR_TRAILER:
        break;

    case OPS_PTAG_CT_UNARMOURED_TEXT:
        break;
        
    case OPS_PTAG_CT_SIGNATURE:
    case OPS_PTAG_CT_SIGNED_CLEARTEXT_HEADER:
    case OPS_PTAG_CT_SIGNED_CLEARTEXT_BODY:
    case OPS_PTAG_CT_SIGNED_CLEARTEXT_TRAILER:
    case OPS_PTAG_CT_SIGNATURE_HEADER:
    case OPS_PTAG_CT_SIGNATURE_FOOTER:
    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
    case OPS_PTAG_CT_LITERAL_DATA_BODY:
        return callback_data_signature(content_, cbinfo);

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
    ops_memory_init(mem_literal_data,0);

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

// EOF
