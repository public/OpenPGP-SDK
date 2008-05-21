/*! \file
  \brief Standard API keyring functions

*/

/** @defgroup StdKeyring Keyring
    \ingroup StandardAPI

    @defgroup StdKeyringFile Keyring File Operations
    \ingroup StdKeyring
    \brief Keyring Open/Read/Write/Close

    Example Usage:
    \code

    // definition of variables
    ops_keyring_t keyring;
    char* filename="~/.gnupg/pubring.gpg";

    // Read keyring from file
    ops_keyring_read_from_file(&keyring,filename);

    // do actions using keyring   
    ... 

    // Free memory alloc-ed in ops_keyring_read_from_file()
    ops_keyring_free();
    \endcode
*/

/**
    @defgroup StdKeyringFind Keyfind Find Operations
    \ingroup StdKeyring
    Find Key or its info within keyring

    Example Usage:
    \code

    // definition of variables
    ops_keyring_t keyring;
    unsigned char* keyid;
    ops_key_data_t *key;

    // Read keyring from file
    ops_keyring_read_from_file(&keyring,"~/.gnupg/pubring.gpg");

    // Search for keys

    // - get Key ID from given userid
    keyid=ops_keyring_find_keyid_by_userid (keyring, "user@domain.com")

    // - now get key from Key ID
    key=ops_keyring_find_key_by_id(keyring, keyid);

    // do something with key
    ...
    
    // Free memory alloc-ed in ops_keyring_read_from_file()
    ops_keyring_free();
    \endcode
 */

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
 #include <unistd.h>
#endif

#include "openpgpsdk/packet.h"
#include "keyring_local.h"

#include "openpgpsdk/accumulate.h"
#include "openpgpsdk/keyring.h"
#include "openpgpsdk/util.h"
#include "openpgpsdk/std_print.h"
#include "openpgpsdk/readerwriter.h"

static ops_parse_cb_return_t
cb_keyring_read(const ops_parser_content_t *content_,
		ops_parse_cb_info_t *cbinfo);

/**
   \ingroup StdKeyringFile
   
   Reads a keyring from a file
   
   \param keyring Ptr to existing keyring
   \param file Filename of keyring
   
   \note Keyring struct must already exist.

   \note Can be used with either a public or secret keyring.

   \note You must call ops_keyring_free() after usage to free alloc-ed memory.

   \note If you call this twice on the same keyring struct, without calling
   ops_keyring_free() between these calls, you will introduce a memory leak.
*/
ops_boolean_t ops_keyring_read_from_file(ops_keyring_t *keyring,const char *filename)
    {
    ops_parse_info_t *pinfo;
    int fd;
    ops_boolean_t res = ops_true;

    memset(keyring,'\0',sizeof *keyring);

    pinfo=ops_parse_info_new();

    // add this for the moment,
    // \todo need to fix the problems with reading signature subpackets later

    //    ops_parse_options(pinfo,OPS_PTAG_SS_ALL,OPS_PARSE_RAW);
    ops_parse_options(pinfo,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);

#ifdef WIN32
    fd=open(filename,O_RDONLY|O_BINARY);
#else
    fd=open(filename,O_RDONLY);
#endif
    if(fd < 0)
        {
        ops_parse_info_delete(pinfo);
        perror(filename);
        return ops_false;
        }

    ops_reader_set_fd(pinfo,fd);

    ops_parse_cb_set(pinfo,cb_keyring_read,NULL);

    if ( ops_parse_and_accumulate(keyring,pinfo) == 0 ) {
        res = ops_false; 
    }

    close(fd);

    ops_parse_info_delete(pinfo);

    return res;
    }

/**
   \ingroup StdKeyring
   
   Reads a keyring from memory
   
   \param keyring Ptr to existing keyring
   \param mem ptr to memory struct containing keyring info
   
   \note Keyring struct must already exist.

   \note Can be used with either a public or secret keyring.

   \note You must call ops_keyring_free() after usage to free alloc-ed memory.

   \note If you call this twice on the same keyring struct, without calling
   ops_keyring_free() between these calls, you will introduce a memory leak.
*/
ops_boolean_t ops_keyring_read_from_mem(ops_keyring_t *keyring, ops_memory_t* mem)
    {
    ops_parse_info_t *pinfo=NULL;
    ops_boolean_t res = ops_true;

    // \todo need to free memory first?
    memset(keyring,'\0',sizeof *keyring);

    pinfo=ops_parse_info_new();
    ops_parse_options(pinfo,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);

    ops_setup_memory_read(&pinfo, mem, cb_keyring_read);

    if ( ops_parse_and_accumulate(keyring,pinfo) == 0 ) 
        {
        res = ops_false; 
        } 
    else 
        {
        res = ops_true;
        }

    ops_teardown_memory_read(pinfo, mem);

    return res;
    }

/**
   \ingroup StdKeyringFile
 
   Frees alloc-ed memory
 
   \param keyring Keyring whose data is to be freed
   
   \note This does not free keyring itself, just the memory alloc-ed in it.
 */
void ops_keyring_free(ops_keyring_t *keyring)
    {
    int n;

    for(n=0 ; n < keyring->nkeys ; ++n)
	ops_keydata_free(&keyring->keys[n]);
    free(keyring->keys);
    keyring->keys=NULL;
    }

/**
   \ingroup StdKeyringFind

   Finds key in keyring from its Key ID

   \param keyring Keyring to be searched
   \param keyid ID of required key

   \return Ptr to key, if found; NULL, if not found
*/
const ops_keydata_t *
ops_keyring_find_key_by_id(const ops_keyring_t *keyring,
			   const unsigned char keyid[OPS_KEY_ID_SIZE])
    {
    int n;

    for(n=0 ; n < keyring->nkeys ; ++n)
        {
        if(!memcmp(keyring->keys[n].key_id,keyid,OPS_KEY_ID_SIZE))
            return &keyring->keys[n];
        }

    return NULL;
    }

/**
   \ingroup StdKeyringFind

   Finds key from its User ID

   \param keyring Keyring to be searched
   \param userid User ID of required key

   \return Ptr to Key, if found; NULL, if not found
*/
const ops_keydata_t *
ops_keyring_find_key_by_userid(const ops_keyring_t *keyring,
				 const char *userid)
    {
    int n=0;
    unsigned int i=0;

    for(n=0 ; n < keyring->nkeys ; ++n)
	for(i=0; i<keyring->keys[n].nuids; i++)
	    {
        //	    printf("[%d][%d] userid %s\n",n,i,keyring->keys[n].uids[i].user_id);
	    if(!strcmp((char *)keyring->keys[n].uids[i].user_id,userid))
	       return &keyring->keys[n];
	    }

    printf("end: n=%d,i=%d\n",n,i);
    return NULL;
    }

/**
   \ingroup StdKeyringList

   List keys in keyring

   \param keyring Keyring to use
   \param match optional string to match

*/

void
ops_keyring_list(const ops_keyring_t* keyring,
		 const char* match)
    {
    int n;
    unsigned int i;
    ops_keydata_t* key;

    printf ("%d keys\n", keyring->nkeys);
    for(n=0,key=&keyring->keys[n] ; n < keyring->nkeys ; ++n,++key)
	{
	for(i=0; i<key->nuids; i++)
	    {
	    if (match)
		printf ("*** match %s\n", match);
	    // if match, compare
	    //	    if(!strcmp((char *)keyring->keys[n].uids[i].user_id,userid))
	    //	       return &keyring->keys[n].keyid[0];
	    if (ops_key_is_secret(key))
		ops_print_secret_keydata(key);
	    else
		ops_print_public_keydata(key);
	    }

	}
    }

/* Static functions */

static ops_parse_cb_return_t
cb_keyring_read(const ops_parser_content_t *content_,
		ops_parse_cb_info_t *cbinfo)
    {
    const ops_parser_content_union_t *content=&content_->content;
    char* passphrase="hello";
    char* pp=ops_mallocz(strlen(passphrase)+1);
    //    char buffer[1024];
    //    size_t n;


    OPS_USED(cbinfo);

    switch(content_->tag)
        {
    case OPS_PARSER_PTAG:
    case OPS_PTAG_CT_ENCRYPTED_SECRET_KEY: // we get these because we didn't prompt
    case OPS_PTAG_CT_SIGNATURE_HEADER:
    case OPS_PTAG_CT_SIGNATURE_FOOTER:
    case OPS_PTAG_CT_SIGNATURE:
    case OPS_PTAG_CT_TRUST:
    case OPS_PARSER_ERRCODE:
        break;

    case OPS_PARSER_CMD_GET_SK_PASSPHRASE:
        strncpy(pp,passphrase,strlen(passphrase));
        *(content->secret_key_passphrase.passphrase)=pp;
        return OPS_KEEP_MEMORY;
        break;

	/*
    default:
	fprintf(stderr,"Unexpected packet tag=%d (0x%x)\n",content_->tag,
		content_->tag);
	assert(0);
	exit(1);
	*/
    default:
	;
	}

    return OPS_RELEASE_MEMORY;
    }

/*\@}*/

/* end of file */
