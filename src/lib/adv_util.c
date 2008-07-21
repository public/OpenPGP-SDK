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

/** \file 
 */

#include <openpgpsdk/util.h>
#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/crypto.h>
#include <openpgpsdk/create.h>
#include <openpgpsdk/errors.h>
#include <stdio.h>
#include <assert.h>

#ifndef WIN32
#include <unistd.h>
#endif

#include <string.h>

#include <openpgpsdk/final.h>

/**
 * Searches the given map for the given type.
 * Returns a human-readable descriptive string if found,
 * returns NULL if not found
 *
 * It is the responsibility of the calling function to handle the
 * error case sensibly (i.e. don't just print out the return string.
 * 
 */
static char *str_from_map_or_null(int type, ops_map_t *map)
    {
    ops_map_t *row;

    for ( row=map; row->string != NULL; row++ )
	if (row->type == type)
	    return row->string;
    return NULL;
    }

/**
 * \ingroup Utils
 *
 * Searches the given map for the given type.
 * Returns a readable string if found, "Unknown" if not.
 */

char *ops_str_from_map(int type, ops_map_t *map)
    {
    char *str;
    str=str_from_map_or_null(type,map);
    if (str)
	return(str);
    else
	return("Unknown");
    }

void hexdump(const unsigned char *src,size_t length)
    {
    while(length--)
	printf("%02X",*src++);
    }

/**
 * \ingroup Utils
 *
 * Initialise OpenPGP:SDK. This <b>must</b> be called before any other
 * OpenPGP:SDK function is used.
 */

void ops_init(void)
    {
    ops_crypto_init();
    }

/**
 * \ingroup Utils
 *
 * Close down OpenPGP:SDK, release any resources under the control of
 * the library. No OpenPGP:SDK function other than ops_init() should
 * be called after this function.
 */

void ops_finish(void)
    {
    ops_crypto_finish();
    }

/** Arguments for reader_fd
 */
typedef struct
    {
    int fd; /*!< file descriptor */
    } reader_fd_arg_t;

/**
 * \ingroup Parse
 *
 * ops_reader_fd() attempts to read up to "plength" bytes from the file 
 * descriptor in "parse_info" into the buffer starting at "dest" using the
 * rules contained in "flags"
 *
 * \param	dest	Pointer to previously allocated buffer
 * \param	plength Number of bytes to try to read
 * \param	flags	Rules about reading to use
 * \param	parse_info	Gets cast to ops_reader_fd_arg_t
 *
 * \return	OPS_R_EOF 	if no bytes were read
 * \return	OPS_R_PARTIAL_READ	if not enough bytes were read, and OPS_RETURN_LENGTH is set in "flags"
 * \return	OPS_R_EARLY_EOF	if not enough bytes were read, and OPS_RETURN_LENGTH was not set in "flags"
 * \return	OPS_R_OK	if expected length was read
 * \return 	OPS_R_ERROR	if cannot read
 *
 * OPS_R_EARLY_EOF and OPS_R_ERROR push errors on the stack
 *
 * \sa enum opt_reader_ret_t
 *
 * \todo change arg_ to typesafe? 
 */
static int fd_reader(void *dest,size_t length,ops_error_t **errors,
		     ops_reader_info_t *rinfo,ops_parse_cb_info_t *cbinfo)
    {
    reader_fd_arg_t *arg=ops_reader_get_arg(rinfo);
    int n=read(arg->fd,dest,length);

    OPS_USED(cbinfo);

    if(n == 0)
	return 0;

    if(n < 0)
	{
	OPS_SYSTEM_ERROR_1(errors,OPS_E_R_READ_FAILED,"read",
			   "file descriptor %d",arg->fd);
	return -1;
	}

    return n;
    }

static void fd_destroyer(ops_reader_info_t *rinfo)
    { free(ops_reader_get_arg(rinfo)); }

void ops_reader_set_fd(ops_parse_info_t *pinfo,int fd)
    {
    reader_fd_arg_t *arg=malloc(sizeof *arg);

    arg->fd=fd;
    ops_reader_set(pinfo,fd_reader,fd_destroyer,arg);
    }

typedef struct
    {
    const unsigned char *buffer;
    size_t length;
    size_t offset;
    } reader_mem_arg_t;

static int mem_reader(void *dest,size_t length,ops_error_t **errors,
		      ops_reader_info_t *rinfo,ops_parse_cb_info_t *cbinfo)
    {
    reader_mem_arg_t *arg=ops_reader_get_arg(rinfo);
    unsigned n;

    OPS_USED(cbinfo);
    OPS_USED(errors);

    if(arg->offset+length > arg->length)
	n=arg->length-arg->offset;
    else
	n=length;

    if(n == 0)
	return 0;

    memcpy(dest,arg->buffer+arg->offset,n);
    arg->offset+=n;

    return n;
    }

static void mem_destroyer(ops_reader_info_t *rinfo)
    { free(ops_reader_get_arg(rinfo)); }

// Note that its the caller's responsibility to ensure buffer continues to
// exist
void ops_reader_set_memory(ops_parse_info_t *pinfo,const void *buffer,
			   size_t length)
    {
    reader_mem_arg_t *arg=malloc(sizeof *arg);

    arg->buffer=buffer;
    arg->length=length;
    arg->offset=0;
    ops_reader_set(pinfo,mem_reader,mem_destroyer,arg);
    }

void *ops_mallocz(size_t n)
    {
    void *m=malloc(n);

    memset(m,'\0',n);

    return m;
    }

typedef struct
    {
    unsigned short sum;
    } sum16_arg_t;

static int sum16_reader(void *dest_,size_t length,ops_error_t **errors,
			ops_reader_info_t *rinfo,ops_parse_cb_info_t *cbinfo)
    {
    const unsigned char *dest=dest_;
    sum16_arg_t *arg=ops_reader_get_arg(rinfo);
    int r=ops_stacked_read(dest_,length,errors,rinfo,cbinfo);
    int n;

    if(r < 0)
	return r;

    for(n=0 ; n < r ; ++n)
	arg->sum=(arg->sum+dest[n])&0xffff;

    return r;
    }

static void sum16_destroyer(ops_reader_info_t *rinfo)
    { free(ops_reader_get_arg(rinfo)); }

void ops_reader_push_sum16(ops_parse_info_t *pinfo)
    {
    sum16_arg_t *arg=ops_mallocz(sizeof *arg);

    ops_reader_push(pinfo,sum16_reader,sum16_destroyer,arg);
    }

unsigned short ops_reader_pop_sum16(ops_parse_info_t *pinfo)
    {
    sum16_arg_t *arg=ops_reader_get_arg(ops_parse_get_rinfo(pinfo));
    unsigned short sum=arg->sum;

    ops_reader_pop(pinfo);
    free(arg);

    return sum;
    }
