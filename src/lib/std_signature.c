/** \file
 */

#include <assert.h>
#include <fcntl.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#endif

#include "openpgpsdk/armour.h"
#include "openpgpsdk/memory.h"
#include "openpgpsdk/readerwriter.h"
#include "openpgpsdk/signature.h"
#include "openpgpsdk/types.h"

static int debug=0;

#define MAXBUF 1024

void ops_sign_file_as_cleartext(const char* filename, const ops_secret_key_t *skey, const ops_boolean_t overwrite)
    {
    // \todo allow choice of hash algorithams
    // enforce use of SHA1 for now

    unsigned char keyid[OPS_KEY_ID_SIZE];
    ops_create_signature_t *sig=NULL;

    char signed_file[MAXBUF+1];
    char *suffix= "asc";
    int fd_in=0;
    int fd_out=0;
    ops_create_info_t *cinfo=NULL;
    unsigned char buf[MAXBUF];
    int flags=0;

    // open file to sign
#ifdef WIN32
    fd_in=open(filename,O_RDONLY | O_BINARY);
#else
    fd_in=open(filename,O_RDONLY);
#endif
    if(fd_in < 0)
        {
        perror(filename);
        exit(2);
        }
    
    snprintf(signed_file,sizeof signed_file,"%s.%s",filename,suffix);
    flags=O_WRONLY | O_CREAT;
    if (overwrite==ops_true)
        flags |= O_TRUNC;
    else
        flags |= O_EXCL;
#ifdef WIN32
    flags |= O_BINARY;
#endif

    fd_out=open(signed_file,flags, 0600);
    if(fd_out < 0)
        {
        perror(signed_file);
        exit(2);
        }
    
    // set up signature
    sig=ops_create_signature_new();
    ops_signature_start_cleartext_signature(sig,skey,OPS_HASH_SHA1,OPS_SIG_BINARY);

    // set up output file
    cinfo=ops_create_info_new();
    ops_writer_set_fd(cinfo,fd_out); 
    ops_writer_push_clearsigned(cinfo,sig);

    // Do the signing

    for (;;)
        {
        int n=0;
    
        n=read(fd_in,buf,sizeof(buf));
        if (!n)
            break;
        assert(n>=0);
        ops_write(buf,n,cinfo);
        }
    close(fd_in);

    // add signature with subpackets:
    // - creation time
    // - key id
    ops_writer_switch_to_armoured_signature(cinfo);

    ops_signature_add_creation_time(sig,time(NULL));
    ops_keyid(keyid,&skey->public_key);
    ops_signature_add_issuer_key_id(sig,keyid);
    ops_signature_hashed_subpackets_end(sig);

    ops_write_signature(sig,&skey->public_key,skey,cinfo);
    ops_writer_close(cinfo);
    close(fd_out);
    }


/* It is the calling function's responsibility to free signed_cleartext */
/* signed_cleartext should be a NULL pointer when passed in */
void ops_sign_buf_as_cleartext(const char* cleartext, const size_t len, ops_memory_t** signed_cleartext, const ops_secret_key_t *skey)
    {
    // \todo allow choice of hash algorithams
    // enforce use of SHA1 for now

    unsigned char keyid[OPS_KEY_ID_SIZE];
    ops_create_signature_t *sig=NULL;

    ops_create_info_t *cinfo=NULL;
    
    assert(*signed_cleartext==NULL);

    // set up signature
    sig=ops_create_signature_new();
    ops_signature_start_cleartext_signature(sig,skey,OPS_HASH_SHA1,OPS_SIG_BINARY);

    // set up output file
    ops_setup_memory_write(&cinfo, signed_cleartext, len);

    ops_writer_push_clearsigned(cinfo,sig);

    // Do the signing

    ops_write(cleartext,len,cinfo);

    // add signature with subpackets:
    // - creation time
    // - key id
    ops_writer_switch_to_armoured_signature(cinfo);

    ops_signature_add_creation_time(sig,time(NULL));
    ops_keyid(keyid,&skey->public_key);
    ops_signature_add_issuer_key_id(sig,keyid);
    ops_signature_hashed_subpackets_end(sig);

    ops_write_signature(sig,&skey->public_key,skey,cinfo);
    ops_writer_close(cinfo);
    }

void ops_sign_file(const char* input_filename, const char* output_filename, const ops_secret_key_t *skey, const ops_boolean_t use_armour, const ops_boolean_t overwrite)
    {
    // \todo allow choice of hash algorithams
    // enforce use of SHA1 for now

    char *myfilename=NULL;
    unsigned char keyid[OPS_KEY_ID_SIZE];
    ops_create_signature_t *sig=NULL;

    int fd_out=0;
    ops_create_info_t *cinfo=NULL;

    ops_hash_algorithm_t hash_alg=OPS_HASH_SHA1;
    ops_sig_type_t sig_type=OPS_SIG_BINARY;

    ops_memory_t* mem_buf=NULL;
    ops_hash_t* hash=NULL;

    // read input file into buf

    mem_buf=ops_write_buf_from_file(input_filename);

    // setup output filename
    if (!output_filename)
        {
        myfilename=ops_mallocz(strlen(input_filename)+4+1);
        if (use_armour)
            sprintf(myfilename,"%s.asc",input_filename);
        else
            sprintf(myfilename,"%s.gpg",input_filename);
        fd_out=ops_setup_file_write(&cinfo, myfilename, overwrite);
        free(myfilename);
        } 
    else
        {
        fd_out=ops_setup_file_write(&cinfo, output_filename, overwrite);
        }

    // set up signature
    sig=ops_create_signature_new();
    ops_signature_start_message_signature(sig, skey, hash_alg, sig_type);

    //  set armoured/not armoured here
    if (use_armour)
        ops_writer_push_armoured_message(cinfo);

    if (debug)
        { fprintf(stderr, "** Writing out one pass sig\n"); } 

    // write one_pass_sig
    ops_write_one_pass_sig(skey, hash_alg, sig_type, cinfo);

    // hash file contents
    hash=ops_signature_get_hash(sig);
    hash->add(hash, ops_memory_get_data(mem_buf), ops_memory_get_length(mem_buf));
    
    // output file contents as Literal Data packet

    if (debug)
        { fprintf(stderr,"** Writing out data now\n"); }

    ops_write_literal_data_from_buf(ops_memory_get_data(mem_buf), ops_memory_get_length(mem_buf), OPS_LDT_BINARY, cinfo);

    if (debug)
        { fprintf(stderr,"** After Writing out data now\n");}

    // add subpackets to signature
    // - creation time
    // - key id

    ops_signature_add_creation_time(sig,time(NULL));

    ops_keyid(keyid,&skey->public_key);
    ops_signature_add_issuer_key_id(sig,keyid);

    ops_signature_hashed_subpackets_end(sig);

    // write out sig
    ops_write_signature(sig,&skey->public_key,skey,cinfo);

    ops_teardown_file_write(cinfo, fd_out);

    // tidy up
    ops_create_signature_delete(sig);
    ops_memory_free(mem_buf);
    }

// EOF
