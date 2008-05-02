/** \file
 */

#include <openpgpsdk/packet.h>

#define DECLARE_ARRAY(type,arr)	unsigned n##arr; unsigned n##arr##_allocated; type *arr
#define EXPAND_ARRAY(str,arr) do if(str->n##arr == str->n##arr##_allocated) \
				{ \
				str->n##arr##_allocated=str->n##arr##_allocated*2+10; \
				str->arr=realloc(str->arr,str->n##arr##_allocated*sizeof *str->arr); \
				} while(0)

/** ops_keydata_key_t
 */
typedef union
    {
    ops_public_key_t pkey;
    ops_secret_key_t skey;
    } ops_keydata_key_t;
    

typedef struct 
    {
    ops_user_id_t* userid;
    ops_packet_t* packet;
    } sigpacket_t;

// XXX: gonna have to expand this to hold onto subkeys, too...
/** \struct ops_keydata
 * \todo expand to hold onto subkeys
 */
struct ops_keydata
    {
    DECLARE_ARRAY(ops_user_id_t,uids);
    DECLARE_ARRAY(ops_packet_t,packets);
    DECLARE_ARRAY(sigpacket_t, sigs);
    unsigned char key_id[8];
    ops_fingerprint_t fingerprint;
    ops_content_tag_t type;
    ops_keydata_key_t key;
    };
