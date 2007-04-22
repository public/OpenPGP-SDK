#include <openpgpsdk/random.h>

#include <openssl/rand.h>

void ops_random(void *dest,size_t length)
    {
    RAND_bytes(dest,length);
    }
