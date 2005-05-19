/** \file
 */

#include "crypto.h"

void hash_add_int(ops_hash_t *hash,unsigned n,unsigned length)
    {
    while(length--)
	{
	unsigned char c[1];

	c[0]=n >> (length*8);
	hash->add(hash,c,1);
	}
    }
