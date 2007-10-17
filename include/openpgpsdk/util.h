/** \file
 */

#ifndef OPS_UTIL_H
#define OPS_UTIL_H

#include "openpgpsdk/types.h"
#include "openpgpsdk/create.h"
#include "openpgpsdk/packet-parse.h"
#include <stdlib.h>

#define ops_false	0
#define ops_true	1

void hexdump(const unsigned char *src,size_t length);
void ops_reader_set_fd(ops_parse_info_t *pinfo,int fd);
void ops_reader_set_memory(ops_parse_info_t *pinfo,const void *buffer,
			   size_t length);

/* typesafe deconstification */
#ifdef WIN32
static void *_deconst(const void *p)
    { return (void *)p; }
#else 
static inline void *_deconst(const void *p)
    { return (void *)p; }
#endif
#define DECONST(type,p) (((type *(*)(const type *))ops_fcast(_deconst))(p))

char *ops_str_from_map(int code, ops_map_t *map);

/* number of elements in an array */
#define OPS_ARRAY_SIZE(a)	(sizeof(a)/sizeof(*(a)))

/** Allocate zeroed memory */
void *ops_mallocz(size_t n);

// Do a sum mod 65536 of all bytes read (as needed for secret keys)
void ops_reader_push_sum16(ops_parse_info_t *pinfo);
unsigned short ops_reader_pop_sum16(ops_parse_info_t *pinfo);

#endif
