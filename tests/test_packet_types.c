#include "CUnit/Basic.h"
 
#include <openpgpsdk/types.h>
#include "openpgpsdk/packet.h"
#include "openpgpsdk/packet-parse.h"
#include "openpgpsdk/keyring.h"
#include "openpgpsdk/std_print.h"
#include "openpgpsdk/util.h"
#include "openpgpsdk/crypto.h"
#include "openpgpsdk/readerwriter.h"
#include "openpgpsdk/random.h"
#include "../src/advanced/parse_local.h"

#include <openssl/aes.h>
#include <openssl/cast.h>
#include <openssl/sha.h>

#include "tests.h"

static unsigned char* mdc_data=NULL;
static size_t sz_mdc_data=0;
static unsigned char* encrypted_pk_sk=NULL;
static size_t sz_encrypted_pk_sk=0;

static void local_cleanup();

/* 
 * Packet Types initialisation.
 */

int init_suite_packet_types(void)
    {
    // Initialise OPS 
    ops_init();

    // Return success
    return 0;
    }

int clean_suite_packet_types(void)
    {
    /* Close OPS */
    
    ops_finish();

    reset_vars();

    return 0;
    }

static ops_parse_cb_return_t
callback_mdc(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;

    OPS_USED(cbinfo);

	//	ops_print_packet(content_);

    switch(content_->tag)
        {
	case OPS_PTAG_CT_MDC:
        sz_mdc_data=OPS_SHA1_HASH_SIZE;
		mdc_data=ops_mallocz(sz_mdc_data);
        //        print_hash("in callback",content->mdc.data);
		memcpy(mdc_data,content->mdc.data,sz_mdc_data);
		break;

    default:
        return callback_general(content_,cbinfo);
        }

    return OPS_RELEASE_MEMORY;
    }
 
static ops_parse_cb_return_t
callback_encrypted_pk_session_key(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;

    OPS_USED(cbinfo);

	//	ops_print_packet(content_);

    switch(content_->tag)
        {
    case OPS_PTAG_CT_PK_SESSION_KEY:
        break;

	case OPS_PTAG_CT_ENCRYPTED_PK_SESSION_KEY:
        sz_encrypted_pk_sk=sizeof(*encrypted_pk_sk);
		encrypted_pk_sk=ops_mallocz(sz_encrypted_pk_sk);
		memcpy(encrypted_pk_sk,&content->pk_session_key,sz_encrypted_pk_sk);
		break;

    case OPS_PARSER_CMD_GET_SK_PASSPHRASE:
        return callback_cmd_get_secret_key_passphrase(content_,cbinfo);

    case OPS_PARSER_CMD_GET_SECRET_KEY:
        return callback_cmd_get_secret_key(content_,cbinfo);

    default:
        return callback_general(content_,cbinfo);
        }

    return OPS_RELEASE_MEMORY;
    }
 
static ops_parse_cb_return_t
callback_se_ip_data(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    //    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;

    OPS_USED(cbinfo);

    //    ops_print_packet(content_);

    switch(content_->tag)
        {
    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
    case OPS_PTAG_CT_LITERAL_DATA_BODY:
        return callback_literal_data(content_,cbinfo);
        break;

    default:
        return callback_general(content_,cbinfo);
        }

    return OPS_RELEASE_MEMORY;
    }
 
static void test_literal_data_packet_text()
    {
    char* testtext=NULL;
    ops_create_info_t *cinfo;
    ops_parse_info_t *pinfo;
    ops_memory_t *mem;

    //    char *in=ops_mallocz(MAXBUF);
    int rtn=0;

    // create test string
    testtext=create_testtext("literal data packet text");

    /*
     * initialise needed structures for writing into memory
     */

    ops_setup_memory_write(&cinfo,&mem,strlen(testtext));

    /*
     * create literal data packet
     */
    ops_write_literal_data_from_buf((unsigned char *)testtext,strlen(testtext),OPS_LDT_TEXT,cinfo);

    /*
     * initialise needed structures for reading from memory
     */

    ops_setup_memory_read(&pinfo,mem,callback_literal_data);

    // and parse it

    ops_memory_init(mem_literal_data,128);
    ops_parse_options(pinfo,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);
    rtn=ops_parse(pinfo);
    CU_ASSERT(rtn==1);

    /*
     * test it's the same
     */

    CU_ASSERT(strncmp((char *)ops_memory_get_data(mem_literal_data),testtext,MAXBUF)==0);

    // cleanup
    local_cleanup();
    ops_teardown_memory_read(pinfo,mem);
    free (testtext);
    }

static void test_literal_data_packet_data()
    {
    ops_create_info_t *cinfo;
    ops_parse_info_t *pinfo;
    ops_memory_t *mem;

    unsigned char *in=ops_mallocz(MAXBUF);
    int rtn=0;

    // create test data buffer
    create_testdata("literal data packet data", &in[0], MAXBUF);

    /*
     * initialise needed structures for writing into memory
     */

    ops_setup_memory_write(&cinfo,&mem,MAXBUF);

    /*
     * create literal data packet
     */
    ops_write_literal_data_from_buf(in,MAXBUF,OPS_LDT_BINARY,cinfo);

    /*
     * initialise needed structures for reading from memory
     */

    ops_setup_memory_read(&pinfo,mem,callback_literal_data);

    // and parse it

    ops_memory_init(mem_literal_data,128);
    ops_parse_options(pinfo,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);
    rtn=ops_parse(pinfo);
    CU_ASSERT(rtn==1);

    /*
     * test it's the same
     */

    CU_ASSERT(memcmp(ops_memory_get_data(mem_literal_data),in,MAXBUF)==0);

    // cleanup
    local_cleanup();
    ops_teardown_memory_read(pinfo,mem);
    free (in);
    }

static void test_ops_mdc()
	{
	// Modification Detection Code Packet
	// used by SE_IP data packets

	ops_memory_t *mem;
	ops_create_info_t *cinfo;
	ops_parse_info_t *pinfo;
    //	ops_hash_t hash;
	char* plaintext="Text to be hashed in test_ops_mdc";
	int rtn=0;
    size_t sz_preamble;

    ops_crypt_t crypt;
    unsigned char hashed[SHA_DIGEST_LENGTH];
    unsigned char* preamble;
    ops_crypt_any(&crypt, OPS_SA_CAST5);
    ops_encrypt_init(&crypt);

    sz_preamble=crypt.blocksize+2;
    preamble=ops_mallocz(sz_preamble);
    ops_random(preamble, crypt.blocksize);
    preamble[crypt.blocksize]=preamble[crypt.blocksize-2];
    preamble[crypt.blocksize+1]=preamble[crypt.blocksize-1];

	// Write packet to memory
	ops_setup_memory_write(&cinfo,&mem,strlen(plaintext));
    ops_calc_mdc_hash(preamble,sz_preamble,(unsigned char *)plaintext,strlen(plaintext),&hashed[0]);
	ops_write_mdc(hashed,cinfo);

	// Read back and verify contents
	ops_setup_memory_read(&pinfo,mem,callback_mdc);
	ops_parse_options(pinfo,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);
	rtn=ops_parse(pinfo);
    CU_ASSERT(rtn==1);

	// This duplicates the hash done in ops_write_mdc so that we
	// can verify it's been written correctly.

#ifdef TODO
    int x;
    unsigned char hashed[SHA_DIGEST_LENGTH];
    unsigned char c[0];
	ops_hash_any(&hash,OPS_HASH_SHA1);
	hash.init(&hash);
	hash.add(&hash,(unsigned char *)plaintext,strlen(plaintext));
    c[0]=0xD3;
    hash.add(&hash,&c[0],1);   // MDC packet tag
    c[0]=0x14;
    hash.add(&hash,&c[0],1);   // MDC packet len
    x=hash.finish(&hash,&hashed[0]);
    assert(x==SHA_DIGEST_LENGTH);
    //    print_hash("recreated hash",hashed);

    CU_ASSERT(mdc_data!=0);
    if (mdc_data)
        CU_ASSERT(memcmp(mdc_data, hashed, OPS_SHA1_HASH_SIZE)==0);
#endif

	// clean up
    local_cleanup();
    ops_teardown_memory_read(pinfo,mem);
	}

static void test_ops_se_ip()
    {
    ops_crypt_t encrypt;
    //    ops_crypt_t decrypt;
    unsigned char *iv=NULL;
    unsigned char *key=NULL;

    // create a simple literal data packet as the encrypted payload
    ops_memory_t *mem_ldt;
    ops_create_info_t *cinfo_ldt;
    char* ldt_text="Test Data string for test_se_ip";

    int rtn=0;
    ops_create_info_t *cinfo;
    ops_parse_info_t *pinfo;
    ops_memory_t *mem;

    ops_setup_memory_write(&cinfo_ldt,&mem_ldt,strlen(ldt_text));
    ops_write_literal_data_from_buf((unsigned char *)ldt_text, strlen(ldt_text),
                           OPS_LDT_TEXT, cinfo_ldt);

    /*
     * write out the encrypted packet
     */
    ops_setup_memory_write(&cinfo,&mem,MAXBUF);

    ops_crypt_any(&encrypt, OPS_SA_CAST5);
    iv=ops_mallocz(encrypt.blocksize);
    encrypt.set_iv(&encrypt, iv);
    key=ops_mallocz(encrypt.keysize); // using made-up key
    snprintf((char *)key, encrypt.keysize, "CAST_KEY");
    encrypt.set_key(&encrypt, key);
    ops_encrypt_init(&encrypt);

    ops_write_se_ip_pktset( ops_memory_get_data(mem_ldt),
                          ops_memory_get_length(mem_ldt),
                          &encrypt, cinfo);

    /*
     * now read it back
     */

    ops_setup_memory_read(&pinfo,mem,callback_se_ip_data);
    ops_parse_options(pinfo,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);

    // \todo hardcode for now
    // note: also hardcoded in ops_write_se_ip_data
    ops_crypt_any(&(pinfo->decrypt), OPS_SA_CAST5);
    pinfo->decrypt.set_iv(&(pinfo->decrypt), iv); // reuse blank iv from encrypt
    pinfo->decrypt.set_key(&(pinfo->decrypt), key); 
    ops_encrypt_init(&pinfo->decrypt);

    ops_memory_init(mem_literal_data,0);
    rtn=ops_parse(pinfo);
    CU_ASSERT(rtn==1);

    /*
     * Callback should now have literal_data parsed from packet
     */

    CU_ASSERT(memcmp(ops_memory_get_data(mem_literal_data),ldt_text, strlen(ldt_text))==0);

    // cleanup
    local_cleanup();
    ops_teardown_memory_read(pinfo,mem);
    ops_memory_free(mem_ldt);
    }

static void test_ops_pk_session_key()
    {
    ops_pk_session_key_t *encrypted_pk_session_key;
    ops_create_info_t *cinfo;
    ops_parse_info_t *pinfo;
    ops_memory_t *mem;
    int rtn=0;
    const ops_key_data_t *pub_key=NULL;

    // setup for write
    ops_setup_memory_write(&cinfo,&mem,MAXBUF);

    // write
    pub_key=ops_keyring_find_key_by_userid(&pub_keyring, alpha_user_id);
    assert(pub_key);

    encrypted_pk_session_key=ops_create_pk_session_key(pub_key);
    CU_ASSERT_FATAL(encrypted_pk_session_key!=NULL);
    ops_write_pk_session_key(cinfo,encrypted_pk_session_key);

    // setup for read
    ops_setup_memory_read(&pinfo,mem,callback_encrypted_pk_session_key);

    // read
    rtn=ops_parse(pinfo);
    CU_ASSERT(rtn==1);

    // test
    CU_ASSERT(memcmp(encrypted_pk_session_key, encrypted_pk_sk, sz_encrypted_pk_sk)==0);

    // cleanup
    local_cleanup();
    ops_teardown_memory_read(pinfo,mem);
    }

#ifdef XXX
static void test_ops_encrypted_pk_sk()
    {
    ops_pk_session_key_t *encrypted_pk_session_key;
    ops_create_info_t *cinfo;
    ops_parse_info_t *pinfo;
    ops_memory_t *mem;
    int rtn=0;

    // setup for write
    ops_setup_memory_write(&cinfo,&mem,MAXBUF);

    // write
    const ops_key_data_t *pub_key=ops_keyring_find_key_by_userid(&pub_keyring, alpha_user_id);
    assert(pub_key);

    encrypted_pk_session_key=ops_create_pk_session_key(pub_key);
    ops_write_pk_session_key(cinfo,encrypted_pk_session_key);

    // setup for read
    ops_setup_memory_read(&pinfo,mem,callback_encrypted_pk_session_key);

    // read
    rtn=ops_parse(pinfo);
    CU_ASSERT(rtn==1);

    // test
    CU_ASSERT(memcmp(encrypted_pk_session_key, encrypted_pk_sk, sz_encrypted_pk_sk)==0);

    // cleanup
    local_cleanup();
    ops_teardown_memory_read(pinfo,mem);
    }
#endif

CU_pSuite suite_packet_types()
{
    CU_pSuite suite = NULL;

    suite = CU_add_suite("Packet Types Suite", init_suite_packet_types, clean_suite_packet_types);
    if (!suite)
	    return NULL;

    // add tests to suite
    
    if (NULL == CU_add_test(suite, "Tag 11: Literal Data packet in Text mode", test_literal_data_packet_text))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Tag 11: Literal Data packet in Data mode", test_literal_data_packet_data))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Tag 19: Modification Detection Code packet", test_ops_mdc))
	    return NULL;

    if (NULL == CU_add_test(suite, "Tag 20: Sym. Encrypted Integrity Protected Data packet", test_ops_se_ip))
	    return NULL;

    if (NULL == CU_add_test(suite, "Tag 1: PK Encrypted Session Key packet", test_ops_pk_session_key))
	    return NULL;

    return suite;
}

static void local_cleanup()
    {
    //    ops_memory_init(mem_literal_data);

    if (mdc_data)
        {
        free(mdc_data);
        mdc_data=NULL;
        }
    }

/*
static void print_hash(char* str, unsigned char* data)
    {
    fprintf(stderr, "\n%s: \n", str);
	int i=0;
	for (i=0; i<OPS_SHA1_HASH_SIZE; i++)
		{
		fprintf(stderr,"0x%2x ",data[i]);
		}
	fprintf(stderr,"\n");
    }
*/

