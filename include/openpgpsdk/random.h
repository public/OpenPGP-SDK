#ifdef WIN32
#include <malloc.h>
#else
#include <unistd.h>
#endif

void ops_random(void *dest,size_t length);
