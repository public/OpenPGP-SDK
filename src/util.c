#include "util.h"
#include <stdio.h>

void hexdump(const unsigned char *src,size_t length)
    {
    while(length--)
	printf("%02X",*src++);
    }

