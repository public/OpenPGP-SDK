/** \file
 */

#include <openpgpsdk/errors.h>
#include <openpgpsdk/util.h>
#include <stdlib.h>

/** \ingroup Errors
 */

static ops_error_map_t error_map_english[] = 
    {
    { OPS_E_OK, "No error" },

    { OPS_E_R,	"Reader Error" },
    { OPS_E_R_READ_FAILED, "Read failed" },

    { OPS_E_W,	"Writer Error" },

    { OPS_E_P,	"Parser Error" },
    { OPS_E_P_NOT_ENOUGH_DATA, "Not enough data left" },

    { OPS_E_C,	"Creator Error" },

    { (int) NULL,		(char *)NULL }, /* this is the end-of-array marker */
    };

static ops_errcode_name_map_t errcode_name_map_english[] = 
    {
    { OPS_E_OK, "OPS_E_OK" },

    { OPS_E_R,	"OPS_E_R" },
    { OPS_E_R_READ_FAILED, "OPS_E_R_READ_FAILED" },

    { OPS_E_W,	"OPS_E_W" },

    { OPS_E_P,	"OPS_E_P" },
    { OPS_E_P_NOT_ENOUGH_DATA, "OPS_E_P_NOT_ENOUGH_DATA" },

    { OPS_E_C,	"OPS_E_C" },

    { (int) NULL,		(char *)NULL }, /* this is the end-of-array marker */
    };

/**
 * \ingroup Errors
 *
 * returns string representing error in specified language
 * \param errcode
 * \param lang
 * \return string or "Unknown"
 */
char *ops_error(ops_errcode_t errcode, ops_lang_t lang)
    {
    if (lang!=OPS_LANG_ENGLISH)
	return("Language not supported\n");

    return(ops_str_from_map((int) errcode, (ops_map_t *) error_map_english));
    }

/**
 * \ingroup Errors
 *
 * returns string representing error code name in specified language
 * \param errcode
 * \param lang
 * \return string or "Unknown"
 */
char *ops_errcode(ops_errcode_t errcode, ops_lang_t lang)
    {
    if (lang!=OPS_LANG_ENGLISH)
	return("Language not supported\n");

    return(ops_str_from_map((int) errcode, (ops_map_t *) errcode_name_map_english));
    }
