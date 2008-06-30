#include <fcntl.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <direct.h>
#endif
#include <openpgpsdk/readerwriter.h>
#include "parse_local.h"

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


int ops_setup_file_write(ops_create_info_t **cinfo, char* filename)
    {
    int fd;
    /*
     * initialise needed structures for writing to file
     */

#ifdef WIN32
    fd=open(filename,O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
#else
    fd=open(filename,O_WRONLY | O_CREAT | O_EXCL, 0600);
#endif
    if(fd < 0)
        {
        perror(filename);
        exit(2);
        }
    
    *cinfo=ops_create_info_new();

    ops_writer_set_fd(*cinfo,fd);

    return fd;
    }

void ops_teardown_file_write(ops_create_info_t *cinfo, int fd)
    {
    close(fd);
    ops_create_info_delete(cinfo);
    }

int ops_setup_file_append(ops_create_info_t **cinfo, char* filename)
    {
    int fd;
    /*
     * initialise needed structures for writing to file
     */

#ifdef WIN32
    fd=open(filename,O_WRONLY | O_APPEND | O_BINARY, 0600);
#else
    fd=open(filename,O_WRONLY | O_APPEND, 0600);
#endif
    if(fd < 0)
        {
        perror(filename);
        exit(2);
        }
    
    *cinfo=ops_create_info_new();

    ops_writer_set_fd(*cinfo,fd);

    return fd;
    }

void ops_teardown_file_append(ops_create_info_t *cinfo, int fd)
    {
    close(fd);
    ops_create_info_delete(cinfo);
    }

int ops_setup_file_read(ops_parse_info_t **pinfo, char *filename,
                        void* arg,
                        ops_parse_cb_return_t callback(const ops_parser_content_t *, ops_parse_cb_info_t *),
                        ops_boolean_t accumulate)
    {
    int fd=0;
    /*
     * initialise needed structures for reading
     */

#ifdef WIN32
    fd=open(filename,O_RDONLY | O_BINARY);
#else
    fd=open(filename,O_RDONLY);
#endif
    if (fd < 0)
        return ops_false;

    *pinfo=ops_parse_info_new();
    ops_parse_cb_set(*pinfo,callback,arg);
    ops_reader_set_fd(*pinfo,fd);

    if (accumulate)
        (*pinfo)->rinfo.accumulate=ops_true;

    return fd;
    }

void ops_teardown_file_read(ops_parse_info_t *pinfo, int fd)
    {
    close(fd);
    ops_parse_info_delete(pinfo);
    }

