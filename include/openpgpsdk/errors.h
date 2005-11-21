/** \file
 */

#ifndef OPS_ERRORS
#define OPS_ERRORS

#include "openpgpsdk/types.h"

/** error codes */
typedef enum 
    {
    OPS_E_OK=0x0000,	/* no error */
    OPS_E_FAIL=0x0001,	/* general error */
    OPS_E_SYSTEM_ERROR=0x0002, /* system error, look at errno for details */

    /* reader errors */
    OPS_E_R=0x1000,	/* general reader error */
    OPS_E_R_READ_FAILED	=OPS_E_R+1,
    OPS_E_R_EARLY_EOF	=OPS_E_R+2,

    /* writer errors */
    OPS_E_W=0x2000,	/* general writer error */
    OPS_E_W_WRITE_FAILED = OPS_E_W+1,
    OPS_E_W_WRITE_TOO_SHORT = OPS_E_W+2,

    /* parser errors */
    OPS_E_P=0x3000,	/* general parser error */
    OPS_E_P_NOT_ENOUGH_DATA=OPS_E_P+1,

    /* creator errors */
    OPS_E_C=0x4000,	/* general creator error */
    } ops_errcode_t;

/** ops_errcode_name_map_t */
typedef ops_map_t ops_errcode_name_map_t;

/** one entry in a linked list of errors */
typedef struct ops_error
    {
    ops_errcode_t errcode;
    int errno;	/*!< irrelevent unless errcode == OPS_E_SYSTEM_ERROR */
    char *comment;
    const char *file;
    int line;
    struct ops_error *next;
    } ops_error_t;

char *ops_errcode(const ops_errcode_t errcode);

void push_error(ops_error_t **errstack,ops_errcode_t errcode,int errno,
		const char *file,int line,const char *comment,...);
void print_error(ops_error_t *err);
void print_errors(ops_error_t *errstack);

#define ops_system_error_1(err,code,syscall,fmt,arg)	do { push_error(err,OPS_E_SYSTEM_ERROR,errno,__FILE__,__LINE__,syscall); push_error(err,code,0,__FILE__,__LINE__,fmt,arg); } while(0)
#define ops_error_1(err,code,fmt,arg)	do { push_error(err,code,0,__FILE__,__LINE__,fmt,arg); } while(0)

#endif /* OPS_ERRORS */
