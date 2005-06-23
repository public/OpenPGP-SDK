
/** @defgroup PublicAPI Public API
 * These functions are public and available for external use.
 * @{
 */
/**
 * @defgroup Parse Parse
 * These functions allow an OpenPGP object (for example, an OpenPGP message or keyring) to be parsed.
 *
 * \par Usage 1 : To Parse an input stream (discarding parsed data)
 * - Configure an ops_parse_options_t structure
 *   - Set "Reader" function and args (to get the data)
 *   - Set "Callback" function and args (to do something useful with the parsed data)
 * - Call ops_parse_options() to specify whether individual subpacket types are to parsed, left raw or ignored
 * - Finally, call ops_parse() 
 *
 * \par Usage 2 : To Parse an input stream (storing parsed data in keyring)
 * - Get keyring
 * - Configure an ops_parse_options_t structure
 *   - Set "Reader" function and args (to get the data)
 *   - No need to set "Callback" function and args 
 * - No need to call ops_parse_options() to specify whether individual subpacket types are to parsed, left raw or ignored
 * - Call ops_parse_and_accumulate() to populate keyring
 * - Don't forget to call ops_keyring_free() when you've finished with the keyring to release the memory.
 * 
 * \par Readers:
 * - ops_reader_fd() is one reader function provided by this library to read from an open file. 
 * - Users may define their own readers.
 *
 * @ingroup PublicAPI
 */
/**
 * @defgroup Create Create
 * These functions allow an OpenPGP object to be created. 
 *
 * The low-level functions are provided to enable flexible usage.
 * Higher-level functions which bundle several functions together into 
 * common operations may be added in the future.
 *
 * \par Example Usage 1 : To create an unsigned RSA public key with user id:
 * - Get the key parameters (creation time, modulus, exponent)
 * - Get the userid
 * - Configure an ops_writer_fd_arg_t structure
 *   - Set "Writer" function
 * - Call ops_write_rsa_public_key()
 * - Call ops_write_user_id()
 *
 * \par Writers:
 * - ops_writer_fd() is one writer function provided by this library to write to an open file. 
 * - Users may define their own writers.
 *
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
 * @defgroup IntCreate Create
 * Used in Create functions
 *
 * @ingroup PublicInternal
 */
/**
 * @}
 */

/** @defgroup Internal Internal API
 * These functions are static.
 * @{
 */
/**
 * @defgroup Callbacks Callbacks
 * These callback functions are used when parsing or creating.
 * @ingroup Internal
 */
/**
 * @}
 */

