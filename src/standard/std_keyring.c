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
    ops_keyring_read(&keyring,filename);

    // do actions using keyring   
    ... 

    // Free memory alloc-ed in ops_keyring_read()
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
    ops_keyring_read(&keyring,"~/.gnupg/pubring.gpg");

    // Search for keys

    // - get Key ID from given userid
    keyid=ops_keyring_find_keyid_by_userid (keyring, "user@domain.com")

    // - now get key from Key ID
    key=ops_keyring_find_key_by_id(keyring, keyid);

    // do something with key
    ...
    
    // Free memory alloc-ed in ops_keyring_read()
    ops_keyring_free();
    \endcode
 */

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "openpgpsdk/packet.h"
#include "keyring_local.h"

#include "openpgpsdk/accumulate.h"
#include "openpgpsdk/keyring.h"
#include "openpgpsdk/util.h"

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
void ops_keyring_read(ops_keyring_t *keyring,const char *file)
    {
    ops_parse_info_t *pinfo;
    int fd;

    memset(keyring,'\0',sizeof *keyring);

    pinfo=ops_parse_info_new();

    fd=open(file,O_RDONLY);
    if(fd < 0)
	{
	perror(file);
	exit(1);
	}

    ops_reader_set_fd(pinfo,fd);

    ops_parse_cb_set(pinfo,cb_keyring_read,NULL);

    ops_parse_and_accumulate(keyring,pinfo);

    close(fd);

    ops_parse_info_delete(pinfo);
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
	ops_key_data_free(&keyring->keys[n]);
    free(keyring->keys);
    keyring->keys=NULL;
    }

/**
   \ingroup StdKeyringFind

   Finds key in keyring from its Key ID

   \param keyring Keyring to be searched
   \param keyid ID of required key

   \return Ptr to key, if found; NULL, if not found

   \note This ptr references the key inside the keyring, so take care if changing it.
*/
ops_key_data_t *
ops_keyring_find_key_by_id(const ops_keyring_t *keyring,
			   const unsigned char keyid[OPS_KEY_ID_SIZE])
    {
    int n;

    for(n=0 ; n < keyring->nkeys ; ++n)
	if(!memcmp(keyring->keys[n].keyid,keyid,OPS_KEY_ID_SIZE))
	    return &keyring->keys[n];

    return NULL;
    }

/**
   \ingroup StdKeyringFind

   Finds key's Key ID from its User ID

   \param keyring Keyring to be searched
   \param userid User ID of required key

   \return Ptr to Key ID, if found; NULL, if not found

   \note This ptr references the key inside the keyring, so take care if changing it.
*/
unsigned char *
ops_keyring_find_keyid_by_userid(const ops_keyring_t *keyring,
				 const char *userid)
    {
    int n;
    unsigned int i;

    for(n=0 ; n < keyring->nkeys ; ++n)
	for(i=0; i<keyring->keys[n].nuids; n++)
	    {
	    printf("[%d][%d] userid %s\n",
		   n,i,
		   keyring->keys[n].uids[i].user_id);
	    if(!strcmp((char *)keyring->keys[n].uids[i].user_id,userid))
	       return &keyring->keys[n].keyid[0];
	    }

    printf("end: n=%d,i=%d\n",n,i);
    return NULL;
    }

static ops_parse_cb_return_t
cb_keyring_read(const ops_parser_content_t *content_,
		ops_parse_cb_info_t *cbinfo)
    {
    //    const ops_parser_content_union_t *content=&content_->content;
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
	// we don't want to prompt when reading the keyring
	break;

    default:
	fprintf(stderr,"Unexpected packet tag=%d (0x%x)\n",content_->tag,
		content_->tag);
	assert(0);
	exit(1);
	}

    return OPS_RELEASE_MEMORY;
    }

/*\@}*/

/* end of file */
