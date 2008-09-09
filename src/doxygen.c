/*! \mainpage Documentation
 *
 * The OpenPGP::SDK library has 2 APIs (High Level and Core), which can be used interchangeably by a user of the library. 

There are also some functions documented here as Internal API, which will be of use to OpenPGP::SDK developers.

\section section_highlevel_api The High-Level API

The High-Level API provides easy access to common crypto tasks. 

Examples are:

- "find the key in the keyring corresponding to this id"
- "sign this text with that key".

It is built on functions offered by the Core API.

Developers should initially consider using the High-Level API, unless they need the additional control available in the Core API.

- \ref HighLevelAPI : follow this link for more details

\section section_core_api The Core API

The Core API offers detailed control over all aspects of the SDK.

- \ref CoreAPI : follow this link for more details

\section section_internal_api The Internal API

The Internal API contains functions for use by SDK developers.

- \ref InternalAPI: follow this link for more details

*/

/** @defgroup HighLevelAPI High Level API
\brief This API provides basic high-level functionality, which should be
suitable for most users. 

If you want more fine-grained control, consider using the Core API.

*/

/** @defgroup CoreAPI Core API
This API provides detailed control over all aspects of the SDK.

You may find that the easier-to-use High Level API meets your needs.
*/

/** @defgroup InternalAPI Internal API
This API provides code used by SDK developers.
*/

/** \defgroup HighLevel_Signature Signatures and Verification
    \ingroup HighLevelAPI
 */
    
/** \defgroup HighLevel_SignatureSign Sign File or Buffer
    \ingroup HighLevel_Signature
 */
    
/** \defgroup HighLevel_SignatureVerify Verify File or Buffer
    \ingroup HighLevel_Signature
 */
    
/** \defgroup HighLevel_SignatureDetails Verify Signature Details
    \ingroup HighLevel_Signature
 */
    
/** \defgroup HighLevel_Crypt Encryption and Decryption
    \ingroup HighLevelAPI
 */
    
/** \defgroup HighLevel_Supported Supported Algorithms
    \ingroup HighLevelAPI
 */
    
/** \defgroup HighLevel_Errors Error Handling
    \ingroup HighLevelAPI
 */
    
/** \defgroup HighLevel_Memory Memory
    \ingroup HighLevelAPI
 */
    
/**
    \defgroup HighLevel_Keyring Keyring
    \ingroup HighLevelAPI
*/

/**
    \defgroup HighLevel_Print Print
    \ingroup HighLevelAPI
*/

/**
    \defgroup HighLevel_General General
    \ingroup HighLevelAPI
*/

/**
    \defgroup HighLevel_KeyringRead Read Keyring
    \ingroup HighLevel_Keyring
*/

/**
    \defgroup HighLevel_KeyringList List Keyring
    \ingroup HighLevel_Keyring
*/

/**
    \defgroup HighLevel_KeyringFind Find Key
    \ingroup HighLevel_Keyring
*/

/**
    \defgroup HighLevel_KeyGenerate Generate Key
    \ingroup HighLevel_Keyring
*/

/**
    \defgroup HighLevel_KeyWrite Write Key
    \ingroup HighLevel_Keyring
*/

/**
    \defgroup HighLevel_KeyGeneral Other Key Functions
    \ingroup HighLevel_Keyring
*/

/**
    \defgroup HighLevel_KeyringMemory Memory Ops
    \ingroup HighLevel_Keyring
*/

/**
   \defgroup Core_Errors Error Handling
   \ingroup CoreAPI
*/

/**
   \defgroup Core_Readers Readers
   \ingroup CoreAPI
*/

/**
   \defgroup Core_Readers_First First (stacks start with one of these)
   \ingroup Core_Readers
*/

/**
   \defgroup Core_Readers_File File Input
   \ingroup Core_Readers_First
*/

/**
   \defgroup Core_Readers_Memory Memory Input
   \ingroup Core_Readers_First
*/

/**
   \defgroup Core_Readers_Additional Additional (stacks may use these)
   \ingroup Core_Readers
*/

/**
   \defgroup Core_Readers_Armour Armoured Data
   \ingroup Core_Readers_Additional
*/

/**
   \defgroup Core_Readers_SE Symmetrically-Encrypted Data
   \ingroup Core_Readers_Additional
*/

/**
  \defgroup Core_Readers_SEIP Symmetrically-Encrypted-Integrity-Protected Data
  \ingroup Core_Readers_Additional
*/

/**
   \defgroup HighLevel_Writers Writers
*/

/** \defgroup Core_WritePackets Write OpenPGP packets
    \ingroup CoreAPI
*/

/** \defgroup Core_ReadPackets Read OpenPGP packets
    \ingroup CoreAPI
*/

/** \defgroup Core_Keys Keys and Keyrings
    \ingroup CoreAPI
 */
    
/** \defgroup Core_Hashes Hashes
    \ingroup CoreAPI
 */
    
/** \defgroup Core_Crypto Encryption and Decryption
    \ingroup CoreAPI
 */
    
/** \defgroup Core_Signature Signatures and Verification
    \ingroup CoreAPI
 */
    
/** \defgroup Core_Compress Compression and Decompression
    \ingroup CoreAPI
 */
    
/** \defgroup Core_MPI Functions to do with MPIs
    \ingroup CoreAPI
*/

/** \defgroup Core_Misc Miscellaneous
    \ingroup CoreAPI
 */
    
/** \defgroup Core_Lists Linked Lists
    \ingroup CoreAPI
 */
    
/** \defgroup Core_Memory Memory
    \ingroup CoreAPI
 */
    
/**
   \defgroup Core_Callbacks Callbacks
   \ingroup CoreAPI
*/

/** 
   \defgroup Internal_Readers Readers
   \ingroup InternalAPI
*/

/**
   \defgroup Internal_Readers_Generic Generic
   \ingroup Internal_Readers
*/

/**
  \defgroup Internal_Readers_Hash Hashed Data
  \ingroup Internal_Readers
*/

/**
  \defgroup Internal_Readers_Sum16 Sum16
  \ingroup Internal_Readers
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
 * @defgroup Core_Create Create Structures
 * \ingroup CoreAPI
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

