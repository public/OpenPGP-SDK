
/** @defgroup PublicAPI Public API
 * These functions are public and available for external use.
 * @{
 */
/**
 * @defgroup Parse Parse
 * These functions allow an OpenPGP object (for example, an OpenPGP message or keyring) to be parsed.
 * Usage:
 * - Configure an ops_parse_options_t structure
 *   - "Reader" function and args (to get the data)
 *   - "Callback" function and args (to do something useful with the parsed data)
 * - Call ops_parse_options() to specify whether individual subpacket types are to parsed, left raw or ignored
 * - Finally, call ops_parse() 
 *
 * ops_reader_fd() is one reader function provided by this library to read from an open file. Users may define their own.
 *
 * @ingroup PublicAPI
 */
/**
 * @defgroup Create Create
 * These functions allow an OpenPGP object to be created.
 * @ingroup PublicAPI
 */
/**
 * @defgroup Memory Memory
 * These functions relate to memory usage.
 * @ingroup PublicAPI
 */
/**
 * @defgroup Show Show
 * These functions allow the contents to be displayed in human-readable form.
 * @ingroup PublicAPI
 */
/**
 * @defgroup Utils Utils
 * These functions are of general utility
 * @ingroup PublicAPI
 */
/**
 * @}
 */

/** @defgroup PublicInternal Public-Internal API
 * These functions are public but should not normally be called.
 * @{
 */
/**
 * @}
 */
