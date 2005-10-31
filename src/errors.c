/** \file
 * \brief Error Handling
 */

#include <openpgpsdk/errors.h>

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/** 
 * push_error() pushes the given error on the given errorstack
 *
 * \param err
 * \param code
 * \param errno
 * \param file
 * \param line
 * \param comment
 *
 */

void push_error(ops_error_t **errstack,ops_error_code_t errcode,int errno,
		const char *file,int line,const char *fmt,...)
    {
    // first get the varargs and generate the comment
    char *comment;
    int maxbuf=128;
    va_list args;
    ops_error_t *err;
    
    comment=malloc(maxbuf+1);
    assert(comment);

    va_start(args, fmt);
    vsnprintf(comment,maxbuf+1,fmt,args);
    va_end(args);
    printf("comment: %s\n", comment);

    // alloc a new error and add it to the top of the stack

    err=malloc(sizeof(ops_error_t));
    assert(err);

    err->next=*errstack;
    *errstack=err;

    // fill in the details
    err->errcode=errcode;
    err->errno=errno;
    err->file=file;
    err->line=line;

    err->comment=comment;
    }
