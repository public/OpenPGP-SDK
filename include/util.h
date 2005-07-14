/** \file
 */

#ifndef OPS_UTIL_H
#define OPS_UTIL_H

#include "types.h"
#include <stdlib.h>

#define ops_false	0
#define ops_true	1

/** Arguments for reader_fd
 */
typedef struct
    {
    int fd; /*!< file descriptor */
    } ops_reader_fd_arg_t;

/** Arguments for writer_fd
 */
typedef struct
    {
    int fd; /*!< file descriptor */
    } ops_writer_fd_arg_t;

void hexdump(const unsigned char *src,size_t length);
ops_reader_ret_t ops_reader_fd(unsigned char *dest,unsigned *plength,
			       ops_reader_flags_t flags,void *arg);
ops_writer_ret_t ops_writer_fd(const unsigned char *src,unsigned length,
			       ops_writer_flags_t flags,void *arg_);

/* typesafe deconstification */
static inline void *_deconst(const void *p)
    { return (void *)p; }
#define DECONST(type,p) (((type *(*)(const type *))ops_fcast(_deconst))(p))

char *ops_str_from_map(int code, map_t *map);

#endif
