#ifndef __OPS_READERWRITER_H__
#define __OPS_READERWRITER_H__

#include <openpgpsdk/memory.h>
#include <openpgpsdk/create.h>

void ops_setup_memory_write(ops_create_info_t **cinfo, ops_memory_t **mem, size_t bufsz);
void ops_teardown_memory_write(ops_create_info_t *cinfo, ops_memory_t *mem);

void ops_setup_memory_read(ops_parse_info_t **pinfo, ops_memory_t *mem,
                              ops_parse_cb_return_t callback(const ops_parser_content_t *, ops_parse_cb_info_t *));
void ops_teardown_memory_read(ops_parse_info_t *pinfo, ops_memory_t *mem);

#endif /*OPS_READERWRITER_H__*/
