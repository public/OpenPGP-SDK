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

extern CU_pSuite suite_packet_types();
extern CU_pSuite suite_crypt_mpi();
extern CU_pSuite suite_rsa_decrypt();
extern CU_pSuite suite_rsa_encrypt();

char dir[MAXBUF+1];
ops_keyring_t pub_keyring;
ops_keyring_t sec_keyring;
static char* no_passphrase="";

int main()
    {

    if (CUE_SUCCESS != CU_initialize_registry())
	return CU_get_error();

    if (NULL == suite_packet_types())
        {
        CU_cleanup_registry();
        return CU_get_error();
        }

    /*
    if (NULL == suite_rsa_decrypt()) 
        {
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_rsa_encrypt()) 
        {
        CU_cleanup_registry();
        return CU_get_error();
        }
    */

    // Run tests
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
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
    /*
    static const ops_key_data_t *decrypt_key;
    */

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
        //        pc.content.secret_key_passphrase.secret_key=&(keydata->key.skey);
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
          Will move this into separate stacked callback later
        */
        *(content->secret_key_passphrase.passphrase)=ops_malloc_passphrase(no_passphrase);
        return OPS_KEEP_MEMORY;
        break;
        
    default:
        return callback_general(content_,cbinfo);
	}
    
    return OPS_RELEASE_MEMORY;
    }

