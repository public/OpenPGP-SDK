/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. 
 * 
 * You may obtain a copy of the License at 
 *     http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

ops_boolean_t ops_sign_file_as_cleartext(const char* filename, const ops_secret_key_t *skey, const ops_boolean_t overwrite)
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
    //int flags=0;
    ops_boolean_t rtn=ops_false;

    // open file to sign
#ifdef WIN32
    fd_in=open(filename,O_RDONLY | O_BINARY);
#else
    fd_in=open(filename,O_RDONLY);
#endif
    if(fd_in < 0)
        {
        return ops_false;
        }
    
    // set up output file
    snprintf(signed_file,sizeof signed_file,"%s.%s",filename,suffix);
    fd_out=ops_setup_file_write(&cinfo, signed_file, overwrite);
    if (fd_out < 0)
        { 
        close (fd_in);
        return ops_false; 
        }

    // set up signature
    sig=ops_create_signature_new();
    if (!sig)
        {
        close (fd_in);
        ops_teardown_file_write(cinfo,fd_out);
        return ops_false;
        }

    // \todo could add more error detection here
    ops_signature_start_cleartext_signature(sig,skey,OPS_HASH_SHA1,OPS_SIG_BINARY);
    if (ops_writer_push_clearsigned(cinfo,sig)!=ops_true)
        { return ops_false; }

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
    rtn = ops_writer_switch_to_armoured_signature(cinfo)
        && ops_signature_add_creation_time(sig,time(NULL));
    if (rtn==ops_false)
        {
        ops_teardown_file_write(cinfo,fd_out);
        return ops_false;
        }

    ops_keyid(keyid,&skey->public_key);

    rtn = ops_signature_add_issuer_key_id(sig,keyid)
        && ops_signature_hashed_subpackets_end(sig)
        && ops_write_signature(sig,&skey->public_key,skey,cinfo);

    ops_teardown_file_write(cinfo,fd_out);

    if (rtn==ops_false)
        {
        OPS_ERROR(&cinfo->errors,OPS_E_W,"Cannot sign file as cleartext");
        }
    return rtn;
    }


/* It is the calling function's responsibility to free signed_cleartext */
/* signed_cleartext should be a NULL pointer when passed in */
ops_boolean_t ops_sign_buf_as_cleartext(const char* cleartext, const size_t len, ops_memory_t** signed_cleartext, const ops_secret_key_t *skey)
    {
    ops_boolean_t rtn=ops_false;

    // \todo allow choice of hash algorithams
    // enforce use of SHA1 for now

    unsigned char keyid[OPS_KEY_ID_SIZE];
    ops_create_signature_t *sig=NULL;

    ops_create_info_t *cinfo=NULL;
    
    assert(*signed_cleartext==NULL);

    // set up signature
    sig=ops_create_signature_new();
    if (!sig)
        { 
        return ops_false;
        }

    // \todo could add more error detection here
    ops_signature_start_cleartext_signature(sig,skey,OPS_HASH_SHA1,OPS_SIG_BINARY);

    // set up output file
    ops_setup_memory_write(&cinfo, signed_cleartext, len);

    // Do the signing
    // add signature with subpackets:
    // - creation time
    // - key id
    rtn = ops_writer_push_clearsigned(cinfo,sig)
        && ops_write(cleartext,len,cinfo)
        && ops_writer_switch_to_armoured_signature(cinfo)
        && ops_signature_add_creation_time(sig,time(NULL));

    if (rtn==ops_false)
        {
        return ops_false;
        }

    ops_keyid(keyid,&skey->public_key);

    rtn = ops_signature_add_issuer_key_id(sig,keyid)
        && ops_signature_hashed_subpackets_end(sig)
        && ops_write_signature(sig,&skey->public_key,skey,cinfo)
        && ops_writer_close(cinfo);

    // Note: the calling function must free signed_cleartext
    ops_create_info_delete(cinfo);

    return rtn;
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

ops_memory_t* ops_sign_mem(const void* input, const int input_len, const ops_sig_type_t sig_type, const ops_secret_key_t *skey, const ops_boolean_t use_armour)
    {
    // \todo allow choice of hash algorithams
    // enforce use of SHA1 for now

    unsigned char keyid[OPS_KEY_ID_SIZE];
    ops_create_signature_t *sig=NULL;

    ops_create_info_t *cinfo=NULL;
    ops_memory_t *mem=ops_memory_new();

    ops_hash_algorithm_t hash_alg=OPS_HASH_SHA1;
    //    ops_sig_type_t sig_type=OPS_SIG_BINARY;
    ops_literal_data_type_t ld_type;
    ops_hash_t* hash=NULL;

    // setup literal data packet type
    if (sig_type==OPS_SIG_BINARY)
        ld_type=OPS_LDT_BINARY;
    else
        ld_type=OPS_LDT_TEXT;

    // set up signature
    sig=ops_create_signature_new();
    ops_signature_start_message_signature(sig, skey, hash_alg, sig_type);

    // setup writer
    ops_setup_memory_write(&cinfo, &mem, input_len);

    //  set armoured/not armoured here
    if (use_armour)
        ops_writer_push_armoured_message(cinfo);

    if (debug)
        { fprintf(stderr, "** Writing out one pass sig\n"); } 

    // write one_pass_sig
    ops_write_one_pass_sig(skey, hash_alg, sig_type, cinfo);

    // hash file contents
    hash=ops_signature_get_hash(sig);
    hash->add(hash, input, input_len);
    
    // output file contents as Literal Data packet

    if (debug)
        { fprintf(stderr,"** Writing out data now\n"); }

    ops_write_literal_data_from_buf(input, input_len, ld_type, cinfo);

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

    // tidy up
    ops_writer_close(cinfo);
    ops_create_signature_delete(sig);

    return mem;
    }

// EOF
