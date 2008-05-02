/** \file
 */

#include <assert.h>
#include <string.h>
#include <openpgpsdk/readerwriter.h>

static int debug=0;

typedef struct 
    {
    ops_crypt_t* crypt;
    int free_crypt;
    } crypt_arg_t;

/*
 * This writer simply takes plaintext as input, 
 * encrypts it with the given key
 * and outputs the resulting encrypted text
 */
static ops_boolean_t encrypt_writer(const unsigned char *src,
				      unsigned length,
				      ops_error_t **errors,
				      ops_writer_info_t *winfo)
    {

#define BUFSZ 1024 // arbitrary number
    unsigned char encbuf[BUFSZ];
    unsigned remaining=length;
    unsigned done=0; 

    crypt_arg_t *arg=(crypt_arg_t *)ops_writer_get_arg(winfo);

    if (!ops_is_sa_supported(arg->crypt->algorithm))
        assert(0); // \todo proper error handling

    while (remaining)
        {
        unsigned len = remaining < BUFSZ ? remaining : BUFSZ;
        //        memcpy(buf,src,len); // \todo copy needed here?
        
        arg->crypt->cfb_encrypt(arg->crypt, encbuf, src+done, len);

        if (debug)
            {
            int i=0;
            fprintf(stderr,"WRITING:\nunencrypted: ");
            for (i=0; i<16; i++)
                fprintf(stderr,"%2x ", src[done+i]);
            fprintf(stderr,"\n");
            fprintf(stderr,"encrypted:   ");
            for (i=0; i<16; i++)
                fprintf(stderr,"%2x ", encbuf[i]);
            fprintf(stderr,"\n");
            }

        if (!ops_stacked_write(encbuf,len,errors,winfo))
            {
            if (debug)
                { fprintf(stderr, "encrypted_writer got error from stacked write, returning\n"); }
            return ops_false;
            }
        remaining-=len;
        done+=len;
        }

    return ops_true;
    }

static void encrypt_destroyer (ops_writer_info_t *winfo)
     
    {
    crypt_arg_t *arg=(crypt_arg_t *)ops_writer_get_arg(winfo);
    if (arg->free_crypt)
        free(arg->crypt);
    free (arg);
    }

#ifdef TODO // was the original interface
void ops_writer_push_encrypt_keydata(ops_create_info_t *cinfo,
                             const ops_key_data_t *pub_key)
    {
    // Create arg to be used with this writer
    // Remember to free this in the destroyer

    crypt_arg_t *arg=ops_mallocz(sizeof *arg);

    // Setup the arg

    ops_crypt_t* encrypt=ops_mallocz(sizeof *encrypt);
    ops_crypt_any(encrypt, pub_key->symmetric_algorithm);
    unsigned char *iv=NULL;
    iv=ops_mallocz(encrypt->blocksize);
    encrypt->set_iv(encrypt, iv);
    encrypt->set_key(encrypt, &pub_key->key[0]);
    ops_encrypt_init(encrypt);

    arg->crypt=encrypt;
    arg->freecrypt=1;

    // And push writer on stack
    ops_writer_push(cinfo,encrypt_writer,NULL,encrypt_destroyer,arg);

    }
#endif

void ops_writer_push_encrypt_crypt(ops_create_info_t *cinfo,
                                   ops_crypt_t *crypt)
    {
    // Create arg to be used with this writer
    // Remember to free this in the destroyer

    crypt_arg_t *arg=ops_mallocz(sizeof *arg);

    // Setup the arg

    arg->crypt=crypt;
    arg->free_crypt=0;

    // And push writer on stack
    ops_writer_push(cinfo,encrypt_writer,NULL,encrypt_destroyer,arg);

    }

// EOF
