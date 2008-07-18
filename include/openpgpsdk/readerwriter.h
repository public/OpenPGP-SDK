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
                                   const ops_keydata_t *pub_key);
// Secret Key checksum

void ops_push_skey_checksum_writer(ops_create_info_t *cinfo, ops_secret_key_t *skey);
ops_boolean_t ops_pop_skey_checksum_writer(ops_create_info_t *cinfo);


// memory writing
void ops_setup_memory_write(ops_create_info_t **cinfo, ops_memory_t **mem, size_t bufsz);
void ops_teardown_memory_write(ops_create_info_t *cinfo, ops_memory_t *mem);

// memory reading
void ops_setup_memory_read(ops_parse_info_t **pinfo, ops_memory_t *mem,
                              ops_parse_cb_return_t callback(const ops_parser_content_t *, ops_parse_cb_info_t *));
void ops_teardown_memory_read(ops_parse_info_t *pinfo, ops_memory_t *mem);

// file writing
int ops_setup_file_write(ops_create_info_t **cinfo, const char* filename, ops_boolean_t allow_overwrite);
void ops_teardown_file_write(ops_create_info_t *cinfo, int fd);

// file appending
int ops_setup_file_append(ops_create_info_t **cinfo, const char* filename);
void ops_teardown_file_append(ops_create_info_t *cinfo, int fd);

// file reading
int ops_setup_file_read(ops_parse_info_t **pinfo, const char *filename, void* arg,
                        ops_parse_cb_return_t callback(const ops_parser_content_t *, ops_parse_cb_info_t *), ops_boolean_t accumulate);
void ops_teardown_file_read(ops_parse_info_t *pinfo, int fd);

// useful callbacks
ops_parse_cb_return_t
callback_literal_data(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);
ops_parse_cb_return_t
callback_pk_session_key(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);
ops_parse_cb_return_t
callback_cmd_get_secret_key(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);
ops_parse_cb_return_t
callback_cmd_get_passphrase_from_cmdline(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);

#endif /*OPS_READERWRITER_H__*/
