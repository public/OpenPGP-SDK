/** \file
 * \brief Error Handling
 */

#include <openpgpsdk/errors.h>
#include <openpgpsdk/util.h>

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <openpgpsdk/final.h>

#define ERR(code)	{ code, #code }

static ops_errcode_name_map_t errcode_name_map[] = 
    {
    { OPS_E_OK, "OPS_E_OK" },
    { OPS_E_FAIL, "OPS_E_FAIL" },
    { OPS_E_SYSTEM_ERROR, "OPS_E_SYSTEM_ERROR" },

    { OPS_E_R,	"OPS_E_R" },
    { OPS_E_R_READ_FAILED, "OPS_E_R_READ_FAILED" },
    { OPS_E_R_EARLY_EOF, "OPS_E_R_EARLY_EOF" },

    { OPS_E_W,	"OPS_E_W" },
    { OPS_E_W_WRITE_FAILED, "OPS_E_W_WRITE_FAILED" },
    { OPS_E_W_WRITE_TOO_SHORT, "OPS_E_W_WRITE_TOO_SHORT" },

    { OPS_E_P,	"OPS_E_P" },
    { OPS_E_P_NOT_ENOUGH_DATA, "OPS_E_P_NOT_ENOUGH_DATA" },
    { OPS_E_P_UNKNOWN_TAG,"OPS_E_P_UNKNOWN_TAG" },
    { OPS_E_P_PACKET_CONSUMED,"OPS_E_P_PACKET_CONSUMED" },
    ERR(OPS_E_P_MPI_FORMAT_ERROR),

    { OPS_E_PROTO, "OPS_E_PROTO" },
    { OPS_E_PROTO_BAD_SYMMETRIC_DECRYPT, "OPS_E_PROTO_BAD_SYMMETRIC_DECRYPT" },

    { OPS_E_C,	"OPS_E_C" },

    { (int) NULL,		(char *)NULL }, /* this is the end-of-array marker */
    };

/**
 * \ingroup Errors
 *
 * returns string representing error code name
 * \param errcode
 * \return string or "Unknown"
 */
char *ops_errcode(const ops_errcode_t errcode)
    {
    return(ops_str_from_map((int) errcode, (ops_map_t *) errcode_name_map));
    }

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

void ops_push_error(ops_error_t **errstack,ops_errcode_t errcode,int sys_errno,
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

    // alloc a new error and add it to the top of the stack

    err=malloc(sizeof(ops_error_t));
    assert(err);

    err->next=*errstack;
    *errstack=err;

    // fill in the details
    err->errcode=errcode;
    err->sys_errno=sys_errno;
    err->file=file;
    err->line=line;

    err->comment=comment;
    }

void ops_print_error(ops_error_t *err)
    {
    printf("%s:%d: ",err->file,err->line);
    if(err->errcode==OPS_E_SYSTEM_ERROR)
	printf("system error %d returned from %s()\n",err->sys_errno,
	       err->comment);
    else
	printf("%s, %s\n",ops_errcode(err->errcode),err->comment);
    }

void ops_print_errors(ops_error_t *errstack)
    {
    ops_error_t *err;

    for(err=errstack ; err!=NULL ; err=err->next)
	ops_print_error(err);
    }
