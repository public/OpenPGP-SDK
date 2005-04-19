#ifndef OPS_UTIL_H
#define OPS_UTIL_H

#include "types.h"
#include <stdlib.h>

#define ops_false	0
#define ops_true	1

typedef struct
    {
    int fd;
    } ops_reader_fd_arg_t;

void hexdump(const unsigned char *src,size_t length);
ops_reader_ret_t ops_reader_fd(unsigned char *dest,unsigned *plength,
			       ops_reader_flags_t flags,void *arg);

#endif
