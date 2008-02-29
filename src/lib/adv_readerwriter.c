#include <openpgpsdk/readerwriter.h>

void ops_setup_memory_write(ops_create_info_t **cinfo, ops_memory_t **mem, size_t bufsz)
    {
    /*
     * initialise needed structures for writing to memory
     */

    *cinfo=ops_create_info_new();
    *mem=ops_memory_new();

    ops_memory_init(*mem,bufsz);

    ops_writer_set_memory(*cinfo,*mem);
    }

void ops_teardown_memory_write(ops_create_info_t *cinfo, ops_memory_t *mem)
    {
    ops_create_info_delete(cinfo);
    ops_memory_free(mem);
    }

void ops_setup_memory_read(ops_parse_info_t **pinfo, ops_memory_t *mem,
                              ops_parse_cb_return_t callback(const ops_parser_content_t *, ops_parse_cb_info_t *))
    {
    /*
     * initialise needed structures for reading
     */

    *pinfo=ops_parse_info_new();
    ops_parse_cb_set(*pinfo,callback,NULL);
    ops_reader_set_memory(*pinfo,
                          ops_memory_get_data(mem),
                          ops_memory_get_length(mem));
    }

void ops_teardown_memory_read(ops_parse_info_t *pinfo, ops_memory_t *mem)
    {
    ops_parse_info_delete(pinfo);
    ops_memory_free(mem);
    }


