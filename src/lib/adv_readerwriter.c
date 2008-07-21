/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. 
 * 
 * You may obtain a copy of the License at 
 *     http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fcntl.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <direct.h>
#endif
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include <openpgpsdk/readerwriter.h>
#include "parse_local.h"

/*! \todo descr for CB macro */
/*! \todo check other callback functions to check they match this usage */
#define CB(cbinfo,t,pc)	do { (pc)->tag=(t); if((cbinfo)->cb(pc,(cbinfo)) == OPS_RELEASE_MEMORY) ops_parser_content_free(pc); } while(0)
#define CBP(info,t,pc) CB(&(info)->cbinfo,t,pc)

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
    ops_writer_close(cinfo); // new
    ops_create_info_delete(cinfo);
    ops_memory_free(mem);
    }

void ops_setup_memory_read(ops_parse_info_t **pinfo, ops_memory_t *mem,
                           void* arg,
                           ops_parse_cb_return_t callback(const ops_parser_content_t *, ops_parse_cb_info_t *))
    {
    /*
     * initialise needed structures for reading
     */

    *pinfo=ops_parse_info_new();
    ops_parse_cb_set(*pinfo,callback,arg);
    ops_reader_set_memory(*pinfo,
                          ops_memory_get_data(mem),
                          ops_memory_get_length(mem));
    }

void ops_teardown_memory_read(ops_parse_info_t *pinfo, ops_memory_t *mem)
    {
    ops_parse_info_delete(pinfo);
    ops_memory_free(mem);
    }


int ops_setup_file_write(ops_create_info_t **cinfo, const char* filename, ops_boolean_t allow_overwrite)
    {
    int fd=0;
    int flags=0;

    /*
     * initialise needed structures for writing to file
     */

    flags=O_WRONLY | O_CREAT;
    if (allow_overwrite==ops_true)
        flags |= O_TRUNC;
    else
        flags |= O_EXCL;

#ifdef WIN32
    flags |= O_BINARY;
#endif

    fd=open(filename, flags, 0600);
    if(fd < 0)
        {
        perror(filename);
        return fd;
        }
    
    *cinfo=ops_create_info_new();

    ops_writer_set_fd(*cinfo,fd);

    return fd;
    }

void ops_teardown_file_write(ops_create_info_t *cinfo, int fd)
    {
    ops_writer_close(cinfo); // new
    close(fd);
    ops_create_info_delete(cinfo);
    }

int ops_setup_file_append(ops_create_info_t **cinfo, const char* filename)
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

int ops_setup_file_read(ops_parse_info_t **pinfo, const char *filename,
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
        // if writer enabled, use it
        if (cbinfo->cinfo)
            {
            ops_write(content->literal_data_body.data,
                      content->literal_data_body.length,
                      cbinfo->cinfo);
            }
        /*
        ops_memory_add(mem_literal_data,
                       content->literal_data_body.data,
                       content->literal_data_body.length);
        */
        break;

    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
        // ignore
        break;

    default:
        //        return callback_general(content_,cbinfo);
        break;
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
        assert(cbinfo->crypt.keyring);
        cbinfo->crypt.keydata=ops_keyring_find_key_by_id(cbinfo->crypt.keyring,
                                             content->pk_session_key.key_id);
        if(!cbinfo->crypt.keydata)
            break;
        break;

    default:
        //        return callback_general(content_,cbinfo);
        break;
        }

    return OPS_RELEASE_MEMORY;
    }

ops_parse_cb_return_t
callback_cmd_get_secret_key(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;
    const ops_secret_key_t *secret;
    ops_parser_content_t pc;

    OPS_USED(cbinfo);

//    ops_print_packet(content_);

    switch(content_->tag)
	{
    case OPS_PARSER_CMD_GET_SECRET_KEY:
        cbinfo->crypt.keydata=ops_keyring_find_key_by_id(cbinfo->crypt.keyring,content->get_secret_key.pk_session_key->key_id);
        if (!cbinfo->crypt.keydata || !ops_key_is_secret(cbinfo->crypt.keydata))
            return 0;

        /* do we need the passphrase and not have it? if so, get it */
        if (!cbinfo->crypt.passphrase)
            {
            memset(&pc,'\0',sizeof pc);
            pc.content.secret_key_passphrase.passphrase=&cbinfo->crypt.passphrase;
            CB(cbinfo,OPS_PARSER_CMD_GET_SK_PASSPHRASE,&pc);
            if (!cbinfo->crypt.passphrase)
                {
                fprintf(stderr,"can't get passphrase\n");
                assert(0);
                }
            }

        /* now get the key from the data */
        secret=ops_get_secret_key_from_data(cbinfo->crypt.keydata);
        while(!secret)
            {
            if (!cbinfo->crypt.passphrase)
                {
                /* get the passphrase */
                }
            /* then it must be encrypted */
            secret=ops_decrypt_secret_key_from_data(cbinfo->crypt.keydata,cbinfo->crypt.passphrase);
            }
        
        *content->get_secret_key.secret_key=secret;
        break;

    default:
        //        return callback_general(content_,cbinfo);
        break;
	}
    
    return OPS_RELEASE_MEMORY;
    }

ops_parse_cb_return_t
callback_cmd_get_passphrase_from_cmdline(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    const int max_pp=256;
    char pp[max_pp+1];
    //char *pp=NULL;

    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;

    OPS_USED(cbinfo);

//    ops_print_packet(content_);

    switch(content_->tag)
        {
    case OPS_PARSER_CMD_GET_SK_PASSPHRASE:

        printf("\nEnter passphrase: ");
        fgets(&pp[0],max_pp, stdin);

        *(content->secret_key_passphrase.passphrase)=ops_malloc_passphrase(pp);
        return OPS_KEEP_MEMORY;
        break;
        
    default:
        //        return callback_general(content_,cbinfo);
        break;
	}
    
    return OPS_RELEASE_MEMORY;
    }

// EOF
