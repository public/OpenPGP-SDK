struct ops_reader_info
    {
    ops_reader_t *reader; /*!< the reader function to use to get the
                            data to be parsed */
    ops_reader_destroyer_t *destroyer;
    void *arg; /*!< the args to pass to the reader function */

    ops_boolean_t accumulate:1;	/*!< set to accumulate packet data */
    unsigned char *accumulated;	/*!< the accumulated data */
    unsigned asize;	/*!< size of the buffer */
    unsigned alength;	/*!< used buffer */
    /* XXX: what do we do about offsets into compressed packets? */
    unsigned position; /*!< the offset from the beginning (with this reader) */

    ops_reader_info_t *next;
    };

struct ops_parse_cb_info
    {
    ops_parse_cb_t *cb; /*!< the callback function to use when parsing */
    void *arg; /*!< the args to pass to the callback function */

    ops_parse_cb_info_t *next;
    };

#define NTAGS	0x100
/** \brief Structure to hold information about a packet parse.
 *
 *  This information includes options about the parse:
 *  - whether the packet contents should be accumulated or not
 *  - whether signature subpackets should be parsed or left raw
 *
 *  It contains options specific to the parsing of armoured data:
 *  - whether headers are allowed in armoured data without a gap
 *  - whether a blank line is allowed at the start of the armoured data
 *  
 *  It also specifies :
 *  - the callback function to use and its arguments
 *  - the reader function to use and its arguments
 *
 *  It also contains information about the current state of the parse:
 *  - offset from the beginning
 *  - the accumulated data, if any
 *  - the size of the buffer, and how much has been used
 *
 *  It has a linked list of errors.
 */

struct ops_parse_info
    {
    unsigned char ss_raw[NTAGS/8]; /*!< one bit per signature-subpacket type; 
				    set to get raw data */
    unsigned char ss_parsed[NTAGS/8]; /*!< one bit per signature-subpacket type;
				       set to get parsed data */

    ops_reader_info_t rinfo;
    ops_parse_cb_info_t cbinfo;
    ops_error_t *errors;
    };
