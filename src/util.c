#include "util.h"
#include "crypto.h"
#include <stdio.h>
#include <assert.h>

void hexdump(const unsigned char *src,size_t length)
    {
    while(length--)
	printf("%02X",*src++);
    }

void ops_init(void)
    {
    ops_crypto_init();
    }

void ops_finish(void)
    {
    ops_crypto_finish();
    }
