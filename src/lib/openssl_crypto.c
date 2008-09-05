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

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <assert.h>
#include <stdlib.h>

#include <openpgpsdk/configure.h>
#include <openpgpsdk/crypto.h>
#include <openpgpsdk/keyring.h>
#include <openpgpsdk/readerwriter.h>
#include "keyring_local.h"
#include <openpgpsdk/std_print.h>

#include <openpgpsdk/final.h>

static int debug=0;

void test_secret_key(const ops_secret_key_t *skey)
    {
    RSA* test=RSA_new();

    test->n=BN_dup(skey->public_key.key.rsa.n);
    test->e=BN_dup(skey->public_key.key.rsa.e);

    test->d=BN_dup(skey->key.rsa.d);
    test->p=BN_dup(skey->key.rsa.p);
    test->q=BN_dup(skey->key.rsa.q);

    assert(RSA_check_key(test)==1);
    RSA_free(test);
    }

static void md5_init(ops_hash_t *hash)
    {
    assert(!hash->data);
    hash->data=malloc(sizeof(MD5_CTX));
    MD5_Init(hash->data);
    }

static void md5_add(ops_hash_t *hash,const unsigned char *data,unsigned length)
    {
    MD5_Update(hash->data,data,length);
    }

static unsigned md5_finish(ops_hash_t *hash,unsigned char *out)
    {
    MD5_Final(out,hash->data);
    free(hash->data);
    hash->data=NULL;
    return 16;
    }

static ops_hash_t md5={OPS_HASH_MD5,MD5_DIGEST_LENGTH,"MD5",md5_init,md5_add,
		       md5_finish,NULL};

void ops_hash_md5(ops_hash_t *hash)
    {
    *hash=md5;
    }

static void sha1_init(ops_hash_t *hash)
    {
    if (debug)
        {
        fprintf(stderr,"***\n***\nsha1_init\n***\n");
        }
    assert(!hash->data);
    hash->data=malloc(sizeof(SHA_CTX));
    SHA1_Init(hash->data);
    }

static void sha1_add(ops_hash_t *hash,const unsigned char *data,
		     unsigned length)
    {
    if (debug)
        {
        unsigned int i=0;
        fprintf(stderr,"adding %d to hash:\n ", length);
        for (i=0; i<length; i++)
            {
            fprintf(stderr,"0x%02x ", data[i]);
            if (!((i+1) % 16))
                fprintf(stderr,"\n");
            else if (!((i+1) % 8))
                fprintf(stderr,"  ");
            }
        fprintf(stderr,"\n");
        }
    SHA1_Update(hash->data,data,length);
    }

static unsigned sha1_finish(ops_hash_t *hash,unsigned char *out)
    {
    SHA1_Final(out,hash->data);
    if (debug)
        {
        unsigned i=0;
        fprintf(stderr,"***\n***\nsha1_finish\n***\n");
        for (i=0; i<20; i++)
            fprintf(stderr,"0x%02x ",out[i]);
        fprintf(stderr,"\n");
        }
    free(hash->data);
    hash->data=NULL;
    return 20;
    }

static ops_hash_t sha1={OPS_HASH_SHA1,SHA_DIGEST_LENGTH,"SHA1",sha1_init,
			sha1_add,sha1_finish,NULL};

void ops_hash_sha1(ops_hash_t *hash)
    {
    *hash=sha1;
    }

ops_boolean_t ops_dsa_verify(const unsigned char *hash,size_t hash_length,
			     const ops_dsa_signature_t *sig,
			     const ops_dsa_public_key_t *dsa)
    {
    DSA_SIG *osig;
    DSA *odsa;
    int ret;

    osig=DSA_SIG_new();
    osig->r=sig->r;
    osig->s=sig->s;

    odsa=DSA_new();
    odsa->p=dsa->p;
    odsa->q=dsa->q;
    odsa->g=dsa->g;
    odsa->pub_key=dsa->y;

    ret=DSA_do_verify(hash,hash_length,osig,odsa);
    assert(ret >= 0);

    odsa->p=odsa->q=odsa->g=odsa->pub_key=NULL;
    DSA_free(odsa);
 
    osig->r=osig->s=NULL;
    DSA_SIG_free(osig);

    return ret != 0;
    }

int ops_rsa_public_decrypt(unsigned char *out,const unsigned char *in,
			   size_t length,const ops_rsa_public_key_t *rsa)
    {
    RSA *orsa;
    int n;

    orsa=RSA_new();
    orsa->n=rsa->n;
    orsa->e=rsa->e;

    n=RSA_public_decrypt(length,in,out,orsa,RSA_NO_PADDING);

    orsa->n=orsa->e=NULL;
    RSA_free(orsa);

    return n;
    }

int ops_rsa_private_encrypt(unsigned char *out,const unsigned char *in,
			    size_t length,const ops_rsa_secret_key_t *srsa,
			    const ops_rsa_public_key_t *rsa)
    {
    RSA *orsa;
    int n;

    orsa=RSA_new();
    orsa->n=rsa->n;	// XXX: do we need n?
    orsa->d=srsa->d;
    orsa->p=srsa->q;
    orsa->q=srsa->p;

    /* debug */
    orsa->e=rsa->e;
    // If this isn't set, it's very likely that the programmer hasn't
    // decrypted the secret key. RSA_check_key segfaults in that case.
    // Use ops_decrypt_secret_key_from_data() to do that.
    assert(orsa->d);
    assert(RSA_check_key(orsa) == 1);
    orsa->e=NULL;
    /* end debug */

    n=RSA_private_encrypt(length,in,out,orsa,RSA_NO_PADDING);

    orsa->n=orsa->d=orsa->p=orsa->q=NULL;
    RSA_free(orsa);

    return n;
    }

int ops_rsa_private_decrypt(unsigned char *out,const unsigned char *in,
			    size_t length,const ops_rsa_secret_key_t *srsa,
			    const ops_rsa_public_key_t *rsa)
    {
    RSA *orsa;
    int n;
    char errbuf[1024];

    orsa=RSA_new();
    orsa->n=rsa->n;	// XXX: do we need n?
    orsa->d=srsa->d;
    orsa->p=srsa->q;
    orsa->q=srsa->p;

    /* debug */
    orsa->e=rsa->e;
    assert(RSA_check_key(orsa) == 1);
    orsa->e=NULL;
    /* end debug */

    n=RSA_private_decrypt(length,in,out,orsa,RSA_NO_PADDING);

    //    printf("ops_rsa_private_decrypt: n=%d\n",n);

    errbuf[0]='\0';
    if (n==-1)
        {
        unsigned long err=ERR_get_error();
        ERR_error_string(err,&errbuf[0]);
        fprintf(stderr,"openssl error : %s\n",errbuf);
        }
    orsa->n=orsa->d=orsa->p=orsa->q=NULL;
    RSA_free(orsa);

    return n;
    }

int ops_rsa_public_encrypt(unsigned char *out,const unsigned char *in,
			   size_t length,const ops_rsa_public_key_t *rsa)
    {
    RSA *orsa;
    int n;

    //    printf("ops_rsa_public_encrypt: length=%ld\n", length);

    orsa=RSA_new();
    orsa->n=rsa->n;
    orsa->e=rsa->e;

    //    printf("len: %ld\n", length);
    //    ops_print_bn("n: ", orsa->n);
    //    ops_print_bn("e: ", orsa->e);
    n=RSA_public_encrypt(length,in,out,orsa,RSA_NO_PADDING);

    if (n==-1)
        {
        BIO *fd_out;
        fd_out=BIO_new_fd(fileno(stderr), BIO_NOCLOSE);
        ERR_print_errors(fd_out);
        }

    orsa->n=orsa->e=NULL;
    RSA_free(orsa);

    return n;
    }

void ops_crypto_init()
    {
#ifdef DMALLOC
    CRYPTO_malloc_debug_init();
    CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif
    }

void ops_crypto_finish()
    {
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);
#ifdef DMALLOC
    CRYPTO_mem_leaks_fp(stderr);
#endif
    }

const char *ops_text_from_hash(ops_hash_t *hash)
    { return hash->name; }

ops_boolean_t ops_rsa_generate_keypair(const int numbits, const unsigned long e, ops_keydata_t* keydata)
    {
    ops_secret_key_t *skey=NULL;
    RSA *rsa=NULL;
    BN_CTX *ctx=BN_CTX_new();

    ops_keydata_init(keydata,OPS_PTAG_CT_SECRET_KEY);
    skey=ops_get_writable_secret_key_from_data(keydata);

    // generate the key pair

    rsa=RSA_generate_key(numbits,e,NULL,NULL);

    // populate ops key from ssl key

    skey->public_key.version=4;
    skey->public_key.creation_time=time(NULL);
    skey->public_key.days_valid=0;
    skey->public_key.algorithm= OPS_PKA_RSA;

    skey->public_key.key.rsa.n=BN_dup(rsa->n);
    skey->public_key.key.rsa.e=BN_dup(rsa->e);

    skey->s2k_usage=OPS_S2KU_ENCRYPTED_AND_HASHED;
    skey->s2k_specifier=OPS_S2KS_SALTED;
    //skey->s2k_specifier=OPS_S2KS_SIMPLE;
    skey->algorithm=OPS_SA_CAST5; // \todo make param
    skey->hash_algorithm=OPS_HASH_SHA1; // \todo make param
    skey->octet_count=0;
    skey->checksum=0;

    skey->key.rsa.d=BN_dup(rsa->d);
    skey->key.rsa.p=BN_dup(rsa->p);
    skey->key.rsa.q=BN_dup(rsa->q);
    skey->key.rsa.u=BN_mod_inverse(NULL,rsa->p, rsa->q, ctx);
    assert(skey->key.rsa.u);
    BN_CTX_free(ctx);

    RSA_free(rsa);

    ops_keyid(keydata->key_id, &keydata->key.skey.public_key);
    ops_fingerprint(&keydata->fingerprint, &keydata->key.skey.public_key);

    // Generate checksum

    ops_create_info_t *cinfo=NULL;
    ops_memory_t *mem=NULL;

    ops_setup_memory_write(&cinfo, &mem, 128);

    ops_push_skey_checksum_writer(cinfo, skey);

    switch(skey->public_key.algorithm)
	{
	//    case OPS_PKA_DSA:
	//	return ops_write_mpi(key->key.dsa.x,info);

    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:
	if(!ops_write_mpi(skey->key.rsa.d,cinfo)
	   || !ops_write_mpi(skey->key.rsa.p,cinfo)
	   || !ops_write_mpi(skey->key.rsa.q,cinfo)
	   || !ops_write_mpi(skey->key.rsa.u,cinfo))
	    return ops_false;
	break;

	//    case OPS_PKA_ELGAMAL:
	//	return ops_write_mpi(key->key.elgamal.x,info);

    default:
	assert(0);
	break;
	}

    // close rather than pop, since its the only one on the stack
    ops_writer_close(cinfo);
    ops_teardown_memory_write(cinfo, mem);

    // should now have checksum in skey struct

    // test
    if (debug)
        test_secret_key(skey);

    return ops_true;
    }

ops_keydata_t* ops_rsa_create_selfsigned_keypair(const int numbits, const unsigned long e, ops_user_id_t * userid)
    {
    ops_keydata_t *keydata=NULL;

    keydata=ops_keydata_new();

    if (ops_rsa_generate_keypair(numbits, e, keydata) != ops_true
        || ops_add_selfsigned_userid_to_keydata(keydata, userid) != ops_true)
        {
        ops_keydata_free(keydata);
        return NULL;
        }

    return keydata;
    }

// eof
