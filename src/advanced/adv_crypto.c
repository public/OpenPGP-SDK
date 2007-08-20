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

    fprintf(stderr,"\nDECRYPTING\n");
    fprintf(stderr,"encrypted data     : ");
    for (i=0; i<16; i++)
        fprintf(stderr,"%2x ", encmpibuf[i]);
    fprintf(stderr,"\n");

    n=ops_rsa_private_decrypt(mpibuf,encmpibuf,(BN_num_bits(encmpi)+7)/8,
			      &skey->key.rsa,&skey->public_key.key.rsa);
    assert(n!=-1);

    fprintf(stderr,"decrypted encoded m buf     : ");
    for (i=0; i<16; i++)
        fprintf(stderr,"%2x ", mpibuf[i]);
    fprintf(stderr,"\n");

    if(n <= 0)
	return -1;

    printf(" decrypted=%d ",n);
    hexdump(mpibuf,n);
    printf("\n");

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

    printf("decoded m buf:\n");
    int j;
    for (j=0; j<n-i; j++)
        printf("%2x ",buf[j]);
    printf("\n");

    return n-i;
    }

ops_boolean_t ops_encrypt_mpi(const unsigned char *encoded_m_buf,
                              const size_t sz_encoded_m_buf,
			      const ops_public_key_t *pkey,
			      ops_pk_session_key_parameters_t *skp)
    {
    assert(sz_encoded_m_buf==(size_t) BN_num_bytes(pkey->key.rsa.n));

    unsigned char encmpibuf[8192];
    int n=0;
#ifdef XXX
    unsigned char EM[8192];
    int k;
    unsigned i;

    // implementation of EME-PKCS1-v1_5-ENCODE, as defined in OpenPGP RFC
    
    assert(pkey->algorithm == OPS_PKA_RSA);

    k=BN_num_bytes(pkey->key.rsa.n);
    /*
    printf("k=%d (length in octets of key modulus)\n",k);
    printf("mLen=%d\n",mLen);
    */
    assert(mLen <= k-11);
    if (mLen > k-11)
        {
        fprintf(stderr,"message too long\n");
        return false;
        }

    // output will be written to ??

    // these two bytes defined by RFC
    EM[0]=0x00;
    EM[1]=0x02;

    // add non-zero random bytes of length k - mLen -3
    for(i=2 ; i < k-mLen-1 ; ++i)
        do
            ops_random(EM+i, 1);
        while(EM[i] == 0);

    assert (i >= 8+2);

    EM[i++]=0;

    memcpy(EM+i, M, mLen);
    
    /*
    int i=0;
    fprintf(stderr,"Encoded Message: \n");
    for (i=0; i<mLen; i++)
        fprintf(stderr,"%2x ", EM[i]);
    fprintf(stderr,"\n");
    */

#endif
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
