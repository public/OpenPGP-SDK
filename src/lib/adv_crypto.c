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

#include <openpgpsdk/crypto.h>
#include <openpgpsdk/random.h>

#include <assert.h>
#include <string.h>

#include <openpgpsdk/final.h>

int ops_decrypt_and_unencode_mpi(unsigned char *buf,unsigned buflen,const BIGNUM *encmpi,
		    const ops_secret_key_t *skey)
    {
    unsigned char encmpibuf[8192];
    unsigned char mpibuf[8192];
    unsigned mpisize;
    int n;
    int i;

    mpisize=BN_num_bytes(encmpi);
    /* MPI can't be more than 65,536 */
    assert(mpisize <= sizeof encmpibuf);
    BN_bn2bin(encmpi,encmpibuf);

    assert(skey->public_key.algorithm == OPS_PKA_RSA);

    /*
    fprintf(stderr,"\nDECRYPTING\n");
    fprintf(stderr,"encrypted data     : ");
    for (i=0; i<16; i++)
        fprintf(stderr,"%2x ", encmpibuf[i]);
    fprintf(stderr,"\n");
    */

    n=ops_rsa_private_decrypt(mpibuf,encmpibuf,(BN_num_bits(encmpi)+7)/8,
			      &skey->key.rsa,&skey->public_key.key.rsa);
    assert(n!=-1);

    /*
    fprintf(stderr,"decrypted encoded m buf     : ");
    for (i=0; i<16; i++)
        fprintf(stderr,"%2x ", mpibuf[i]);
    fprintf(stderr,"\n");
    */

    if(n <= 0)
	return -1;

    /*
    printf(" decrypted=%d ",n);
    hexdump(mpibuf,n);
    printf("\n");
    */

    // Decode EME-PKCS1_V1_5 (RFC 2437).

    if(mpibuf[0] != 0 || mpibuf[1] != 2)
        return ops_false;

    // Skip the random bytes.
    for(i=2 ; i < n && mpibuf[i] ; ++i)
        ;

    if(i == n || i < 10)
        return ops_false;

    // Skip the zero
    ++i;

    // this is the unencoded m buf
    if((unsigned)(n-i) <= buflen)
        memcpy(buf,mpibuf+i,n-i);

    /*
    printf("decoded m buf:\n");
    int j;
    for (j=0; j<n-i; j++)
        printf("%2x ",buf[j]);
    printf("\n");
    */

    return n-i;
    }

ops_boolean_t ops_rsa_encrypt_mpi(const unsigned char *encoded_m_buf,
                              const size_t sz_encoded_m_buf,
			      const ops_public_key_t *pkey,
			      ops_pk_session_key_parameters_t *skp)
    {
    assert(sz_encoded_m_buf==(size_t) BN_num_bytes(pkey->key.rsa.n));

    unsigned char encmpibuf[8192];
    int n=0;

    n=ops_rsa_public_encrypt(encmpibuf, encoded_m_buf, sz_encoded_m_buf, &pkey->key.rsa);
    assert(n!=-1);

    if(n <= 0)
	return ops_false;

    skp->rsa.encrypted_m=BN_bin2bn(encmpibuf, n, NULL);

    /*
    fprintf(stderr,"encrypted mpi buf     : ");
    int i;
    for (i=0; i<16; i++)
        fprintf(stderr,"%2x ", encmpibuf[i]);
    fprintf(stderr,"\n");
    */

    return ops_true;
    }
