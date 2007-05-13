#ifndef __TESTS__
#define __TESTS_

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

int mktmpdir();
extern char dir[];
void create_testtext(const char *text, char *buf, const int maxlen);
#define MAXBUF 128

#endif

