/** \file
 */

#include <assert.h>
#include <fcntl.h>
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

void ops_sign_file_as_cleartext(const char* filename, const ops_secret_key_t *skey)
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
    
    // open file to sign
    //    snprintf(myfile,MAXBUF,"%s/%s",filename);
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
    
    snprintf(signed_file,MAXBUF,"%s.%s",filename,suffix);
#ifdef WIN32
    fd_out=open(signed_file,O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
#else
    fd_out=open(signed_file,O_WRONLY | O_CREAT | O_EXCL, 0600);
#endif
    if(fd_out < 0)
        {
        perror(signed_file);
        exit(2);
        }
    
    // set up signature
    sig=ops_create_signature_new();
    ops_signature_start_cleartext_signature(sig,(ops_secret_key_t *)skey,OPS_HASH_SHA1,OPS_SIG_BINARY);

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

    ops_write_signature(sig,(ops_public_key_t *)&skey->public_key,(ops_secret_key_t *)skey,cinfo);
    ops_writer_close(cinfo);
    close(fd_out);
    }

void ops_sign_file(const char* input_filename, const char* output_filename, const ops_secret_key_t *skey, const int use_armour)
    {
    // \todo allow choice of hash algorithams
    // enforce use of SHA1 for now

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

    // 
    // now for output file
#ifdef WIN32
    fd_out=open(output_filename,O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
#else
    fd_out=open(output_filename,O_WRONLY | O_CREAT | O_EXCL, 0600);
#endif
    if(fd_out < 0)
        {
        perror(output_filename);
        exit(2);
        }
    
    // set up signature
    sig=ops_create_signature_new();
    ops_signature_start_message_signature(sig,(ops_secret_key_t *)skey, hash_alg, sig_type);

    // set up output file
    cinfo=ops_create_info_new();
    ops_writer_set_fd(cinfo,fd_out); 

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
    ops_write_signature(sig,(ops_public_key_t *)&skey->public_key,(ops_secret_key_t *)skey,cinfo);
    ops_writer_close(cinfo);
    close(fd_out);

    // tidy up
    ops_create_info_delete(cinfo);
    ops_create_signature_delete(sig);
    ops_memory_free(mem_buf);
    }

// EOF
