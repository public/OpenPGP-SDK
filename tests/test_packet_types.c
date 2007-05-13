#include "CUnit/Basic.h"

#include <openpgpsdk/types.h>
#include "openpgpsdk/packet.h"
#include "openpgpsdk/packet-parse.h"
#include "openpgpsdk/keyring.h"
#include "openpgpsdk/std_print.h"
#include "openpgpsdk/util.h"

#include "tests.h"

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
callback(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {

    OPS_USED(cbinfo);

    // just print it for now
    // \todo read literal data packet into buffer

    ops_print_packet(content_);
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

static void test_literal_data_packet_text()
    {
    char *in=ops_mallocz(MAXBUF);
    ops_create_info_t *cinfo;
    ops_parse_info_t *pinfo;
    ops_memory_t *mem;
    int rtn=0;

    // create test string
    create_testtext("literal data packet", &in[0], MAXBUF);

    /*
     * initialise needed structures for writing
     */

    cinfo=ops_create_info_new();
    mem=ops_memory_new();
    ops_memory_init(mem,MAXBUF);
    ops_writer_set_memory(cinfo,mem);

    /*
     * create literal data packet
     */
    ops_write_literal_data((unsigned char *)in,strlen(in),OPS_LDT_TEXT,cinfo);

    /*
     * initialise needed structures for writing
     */

    pinfo=ops_parse_info_new();
    ops_parse_cb_set(pinfo,callback,NULL);
    ops_reader_set_memory(pinfo,mem->buf,mem->length);

    // and parse it

    ops_parse_options(pinfo,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);
    rtn=ops_parse(pinfo);

    /*
     * test it's the same
     */

    // \todo write a callback to read the literal data into buffer

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
    
    if (NULL == CU_add_test(suite, "Literal Data Text packet", test_literal_data_packet_text))
	    return NULL;
    
    return suite;
}

