/*! \mainpage Documentation
 *
 * The OpenPGP::SDK library has 2 APIs, which can be used interchangeably by a developer.

\section section_std_api The Standard API

The Standard API provides easy access to common crypto tasks. 

Examples are:

- "find the key in the keyring corresponding to this id"
- "sign this text with that key".

It is built on functions offered by the Advanced API.

Developers should initially consider using the Standard API, unless they need the additional control available in the Advanced API.

- \ref StandardAPI : follow this link for more details

\section section_adv_api The Advanced API

The Advanced API offers detailed control over all aspects of the SDK.

- \ref AdvancedAPI : follow this link for more details

*/

/** @defgroup StandardAPI Standard API
This API provides basic high-level functionality, which should be
suitable for most users.

If you want more fine-grained control, consider using the Advanced API.
*/

/** @defgroup AdvancedAPI Advanced API
This API provides detailed control over all aspects of the SDK.

You may find that the easier-to-use Standard API meets your needs.
*/

/**
 * @defgroup Parse Parse
 * \ingroup AdvancedAPI
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
 */
/**
 * @defgroup Create Create
 * \ingroup AdvancedAPI
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
 */
/**
 * @defgroup Memory Memory
 * \ingroup AdvancedAPI
 * These functions relate to memory usage.
 */
/**
 * @defgroup Show Show
 * \ingroup AdvancedAPI
 * These functions allow the contents to be displayed in human-readable form.
 */
/**
 * @defgroup Utils Utils
 * \ingroup AdvancedAPI
 * These functions are of general utility.
 */
/**
 * @defgroup Verify Verify
 * \ingroup AdvancedAPI
 * These functions are for verifying signatures.
 */

/**
 * @defgroup Callbacks Callbacks
 * \ingroup AdvancedAPI
 * These callback functions are used when parsing or creating.
 */

