/** \file
 */

#include "types.h"

#ifndef OPS_ERRORS
#define OPS_ERRORS

typedef enum 
    {
    OPS_E_OK=0x0000,	/* no error */

    OPS_E_FAIL=0x0001,	/* general error */

    /* reader errors */
    OPS_E_R=0x1000,	/* general reader error */
    OPS_E_R_READ_FAILED=OPS_E_R+1,

    /* writer errors */
    OPS_E_W=0x2000,	/* general writer error */

    /* parser errors */
    OPS_E_P=0x3000,	/* general parser error */
    OPS_E_P_NOT_ENOUGH_DATA=OPS_E_P+1,

    /* creator errors */
    OPS_E_C=0x4000,	/* general creator error */
    } ops_errcode_t;

typedef map_t ops_error_map_t;
typedef map_t ops_errcode_name_map_t;


typedef enum 
    {
    OPS_LANG_ENGLISH=1
    } ops_lang_t;

/* Function Declarations */

char *ops_error(ops_errcode_t errcode, ops_lang_t lang);
char *ops_errcode(ops_errcode_t errcode, ops_lang_t lang);

#endif /* OPS_ERRORS */
