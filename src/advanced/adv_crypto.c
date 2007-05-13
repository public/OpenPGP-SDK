#include <openpgpsdk/crypto.h>
#include <openpgpsdk/random.h>

#include <assert.h>
#include <string.h>

#include <openpgpsdk/final.h>

int ops_decrypt_mpi(unsigned char *buf,unsigned buflen,const BIGNUM *encmpi,
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

    n=ops_rsa_private_decrypt(mpibuf,encmpibuf,(BN_num_bits(encmpi)+7)/8,
			      &skey->key.rsa,&skey->public_key.key.rsa);

    if(n <= 0)
	return -1;

    /*
    printf(" decrypt=%d ",n);
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

    if((unsigned)(n-i) <= buflen)
	memcpy(buf,mpibuf+i,n-i);

    return n-i;
    }

ops_boolean_t ops_encrypt_mpi(const unsigned char *buf, size_t buflen,
			      const ops_public_key_t *pkey,
			      ops_pk_session_key_parameters_t *skp)
    {
    unsigned char encmpibuf[8192];
    unsigned char padded[8192];
    int n;
    unsigned i;

    // implementation of EME-PKCS1-v1_5-ENCODE, as defined in OpenPGP RFC
    
    assert(pkey->algorithm == OPS_PKA_RSA);

    n=BN_num_bytes(pkey->key.rsa.n);

    // these two bytes defined by RFC
    padded[0]=0;
    padded[1]=2;
    // add non-zero random bytes of length k - mLen -3
    for(i=2 ; i < n-buflen-1 ; ++i)
	do
	    ops_random(padded+i, 1);
	while(padded[i] == 0);

    assert (i >= 8+2);

    padded[i++]=0;

    memcpy(padded+i, buf, buflen);
    
    n=ops_rsa_public_encrypt(encmpibuf, padded, n, &pkey->key.rsa);

    if(n <= 0)
	return ops_false;

    skp->rsa.encrypted_m=BN_bin2bn(encmpibuf, n, NULL);

    return ops_true;
    }
