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

/** Arguments for reader_fd
 */
typedef struct
    {
    int fd; /*!< file descriptor */
    } ops_reader_fd_arg_t;

void hexdump(const unsigned char *src,size_t length);
ops_reader_ret_t ops_reader_fd(unsigned char *dest,unsigned *plength,
			       ops_reader_flags_t flags,ops_parse_info_t *parse_info);

/* typesafe deconstification */
static inline void *_deconst(const void *p)
    { return (void *)p; }
#define DECONST(type,p) (((type *(*)(const type *))ops_fcast(_deconst))(p))

char *ops_str_from_map(int code, ops_map_t *map);

/* number of elements in an array */
#define OPS_ARRAY_SIZE(a)	(sizeof(a)/sizeof(*(a)))

/** Allocate zeroed memory */
void *ops_mallocz(size_t n);

#endif
