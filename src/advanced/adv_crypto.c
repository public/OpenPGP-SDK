#include <openpgpsdk/crypto.h>

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
