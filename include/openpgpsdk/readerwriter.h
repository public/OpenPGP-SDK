#ifndef __OPS_READERWRITER_H__
#define __OPS_READERWRITER_H__

#include <openpgpsdk/memory.h>
#include <openpgpsdk/create.h>

/**
 * \ingroup Create
 * This struct contains the required information about one writer
 */
struct ops_writer_info
    {
    ops_writer_t *writer;
    ops_writer_finaliser_t *finaliser;
    ops_writer_destroyer_t *destroyer;
    void *arg;
    ops_writer_info_t *next;
    };

/**
 * \ingroup Create
 * This struct contains the required information about how to write this stream
 */
struct ops_create_info
    {
    ops_writer_info_t winfo;
    ops_error_t *errors;	/*!< an error stack */
    };

//
ops_boolean_t ops_write_mdc(const unsigned char *hashed,
                                   ops_create_info_t* info);
ops_boolean_t ops_write_se_ip_pktset(const unsigned char *data,
                                            const unsigned int len,
                                            ops_crypt_t *crypt,
                                            ops_create_info_t *info);
void ops_writer_push_encrypt_crypt(ops_create_info_t *cinfo,
                                   ops_crypt_t *crypt);
void ops_writer_push_encrypt_se_ip(ops_create_info_t *cinfo,
                                   const ops_key_data_t *pub_key);


//
void ops_setup_memory_write(ops_create_info_t **cinfo, ops_memory_t **mem, size_t bufsz);
void ops_teardown_memory_write(ops_create_info_t *cinfo, ops_memory_t *mem);

void ops_setup_memory_read(ops_parse_info_t **pinfo, ops_memory_t *mem,
                              ops_parse_cb_return_t callback(const ops_parser_content_t *, ops_parse_cb_info_t *));
void ops_teardown_memory_read(ops_parse_info_t *pinfo, ops_memory_t *mem);

#endif /*OPS_READERWRITER_H__*/
