#ifndef OPS_UTIL_H
#define OPS_UTIL_H

#include <stdlib.h>

typedef unsigned ops_boolean_t;

#define ops_false	0
#define ops_true	1

void hexdump(const unsigned char *src,size_t length);

#endif
