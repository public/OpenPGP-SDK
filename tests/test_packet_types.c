#include "CUnit/Basic.h"

#include <openpgpsdk/types.h>
#include "openpgpsdk/packet.h"
#include "openpgpsdk/packet-parse.h"
#include "openpgpsdk/keyring.h"
#include "openpgpsdk/std_print.h"
#include "openpgpsdk/util.h"
#include "openpgpsdk/crypto.h"
#include "../src/advanced/parse_local.h"

#include "tests.h"

static unsigned char* data;

#define MAXBUF 128

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

    return 0;
    }

static ops_parse_cb_return_t
callback_literal_data(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;

    OPS_USED(cbinfo);

    //    ops_print_packet(content_);

    // Read data from packet into static buffer
    switch(content_->tag)
        {
    case OPS_PTAG_CT_LITERAL_DATA_BODY:
	data=ops_mallocz(content->literal_data_body.length+1);
	memcpy(data,content->literal_data_body.data,content->literal_data_body.length);
        break;

    case OPS_PARSER_PTAG:
    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
        // ignore
        break;

    default:
	fprintf(stderr,"Unexpected packet tag=%d (0x%x)\n",content_->tag,
		content_->tag);
	assert(0);
        }

    return OPS_RELEASE_MEMORY;
    }
 
static ops_parse_cb_return_t
callback_symmetrically_encrypted_data(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    //ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;

    OPS_USED(cbinfo);

    ops_print_packet(content_);

    switch(content_->tag)
        {
        // ignore
        //        break;

        //    case OPS_PTAG_CT_SE_DATA_BODY:
        //	data=ops_mallocz(content->literal_data_body.length+1);
        //	memcpy(data,content->literal_data_body.data,content->literal_data_body.length);
        //        break;

    case OPS_PARSER_PTAG:
    case OPS_PTAG_CT_SE_DATA_HEADER:
        // ignore
        break;

    default:
	fprintf(stderr,"Unexpected packet tag=%d (0x%x)\n",content_->tag,
		content_->tag);
	assert(0);
        }

    return OPS_RELEASE_MEMORY;
    }
 
// \todo temp place to this. need to work out best place for this struct
// this is a copy of the original definition in adv_memory.c
struct ops_memory
    {
    unsigned char *buf;
    size_t length;
    size_t allocated;
    };

static void init_for_memory_write(ops_create_info_t **cinfo, ops_memory_t **mem)
    {
    /*
     * initialise needed structures for writing
     */

    *cinfo=ops_create_info_new();
    *mem=ops_memory_new();

    ops_memory_init(*mem,MAXBUF);

    ops_writer_set_memory(*cinfo,*mem);
    }

static void init_for_memory_read(ops_parse_info_t **pinfo, ops_memory_t *mem,
                                 ops_parse_cb_return_t callback(const ops_parser_content_t *, ops_parse_cb_info_t *))
    {
    /*
     * initialise needed structures for reading
     */

    *pinfo=ops_parse_info_new();
    ops_parse_cb_set(*pinfo,callback,NULL);
    ops_reader_set_memory(*pinfo,mem->buf,mem->length);
    }


static void test_literal_data_packet_text()
    {
    ops_create_info_t *cinfo;
    ops_parse_info_t *pinfo;
    ops_memory_t *mem;

    char *in=ops_mallocz(MAXBUF);
    int rtn=0;

    // create test string
    create_testtext("literal data packet text", &in[0], MAXBUF);

    /*
     * initialise needed structures for writing into memory
     */

    init_for_memory_write(&cinfo,&mem);

    /*
     * create literal data packet
     */
    ops_write_literal_data((unsigned char *)in,strlen(in),OPS_LDT_TEXT,cinfo);

    /*
     * initialise needed structures for reading from memory
     */

    init_for_memory_read(&pinfo,mem,callback_literal_data);

    // and parse it

    ops_parse_options(pinfo,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);
    rtn=ops_parse(pinfo);

    /*
     * test it's the same
     */

    CU_ASSERT(strncmp((char *)data,in,MAXBUF)==0);

    // cleanup
    ops_memory_free(mem);
    free (in);
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

    init_for_memory_write(&cinfo,&mem);

    /*
     * create literal data packet
     */
    ops_write_literal_data(in,MAXBUF,OPS_LDT_BINARY,cinfo);

    /*
     * initialise needed structures for reading from memory
     */

    init_for_memory_read(&pinfo,mem,callback_literal_data);

    // and parse it

    ops_parse_options(pinfo,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);
    rtn=ops_parse(pinfo);

    /*
     * test it's the same
     */

    CU_ASSERT(memcmp(data,in,MAXBUF)==0);

    // cleanup
    ops_memory_free(mem);
    free (in);
    }

static void test_symmetrically_encrypted_data_packet()
    {
    ops_create_info_t *cinfo;
    ops_parse_info_t *pinfo;
    ops_memory_t *mem;

    unsigned char *in=ops_mallocz(MAXBUF);
    int rtn=0;
 
    // create test data buffer
    create_testdata("symmetrically encrypted data packet", &in[0], MAXBUF);

    /*
     * initialise needed structures for writing into memory
     */

    init_for_memory_write(&cinfo,&mem);

    /*
     * create literal data packet
     */
    ops_write_symmetrically_encrypted_data(in,MAXBUF,cinfo);

    /*
     * initialise needed structures for reading from memory
     */

    init_for_memory_read(&pinfo,mem,callback_symmetrically_encrypted_data);

    // and parse it

    ops_parse_options(pinfo,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);
    // \todo hardcode for now
    // note: also hardcoded in ops_write_symmetrically_encrypted_data
    ops_crypt_any(&(pinfo->decrypt), OPS_SA_AES_256);
    ops_encrypt_init(&pinfo->decrypt);
    rtn=ops_parse(pinfo);

    /*
     * test it's the same
     */

    CU_ASSERT(memcmp(data,in,MAXBUF)==0);

    // cleanup
    ops_memory_free(mem);
    free (in);
    }

CU_pSuite suite_packet_types()
{
    CU_pSuite suite = NULL;

    suite = CU_add_suite("Packet Types Suite", init_suite_packet_types, clean_suite_packet_types);
    if (!suite)
	    return NULL;

    // add tests to suite
    
    if (NULL == CU_add_test(suite, "Literal Data (Text) packet (Tag 11)", test_literal_data_packet_text))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Literal Data (Data) packet (Tag 11)", test_literal_data_packet_data))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Symmetrically Encrypted Data packet (Tag 9)", test_symmetrically_encrypted_data_packet))
	    return NULL;
    
    return suite;
}

