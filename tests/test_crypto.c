#include "CUnit/Basic.h"

#include <openpgpsdk/random.h>
#include "openpgpsdk/std_print.h"
/*
#include <openpgpsdk/types.h>
#include "openpgpsdk/packet.h"
#include "openpgpsdk/packet-parse.h"
#include "openpgpsdk/keyring.h"
#include "openpgpsdk/util.h"
#include "openpgpsdk/crypto.h"
#include "openpgpsdk/readerwriter.h"
#include "../src/advanced/parse_local.h"
#include <openssl/cast.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
*/
 
#include "tests.h"

/*
static unsigned char* literal_data=NULL;
static size_t sz_literal_data=0;
static unsigned char* mdc_data=NULL;
static size_t sz_mdc_data=0;
static unsigned char* encrypted_pk_sk=NULL;
static size_t sz_encrypted_pk_sk=0;

#define MAXBUF 128

static void cleanup();
*/

/* 
 * initialisation
 */

int init_suite_crypto(void)
    {
#ifdef XXX
    char keydetails[MAXBUF+1];
    char keyring_name[MAXBUF+1];
    int fd=0;
    char cmd[MAXBUF+1];

    // Initialise OPS 
    ops_init();

    char *rsa_nopass="Key-Type: RSA\nKey-Usage: encrypt, sign\nName-Real: Alpha\nName-Comment: RSA, no passphrase\nName-Email: alpha@test.com\nKey-Length: 1024\n";
    // Create temp directory
    if (!mktmpdir())
	return 1;

    /*
     * Create a RSA keypair with no passphrase
     */

    snprintf(keydetails,MAXBUF,"%s/%s",dir,"keydetails.alpha");

    if ((fd=open(keydetails,O_WRONLY | O_CREAT | O_EXCL, 0600))<0)
	{
	fprintf(stderr,"Can't create key details\n");
	return 1;
	}

    write(fd,rsa_nopass,strlen(rsa_nopass));
    close(fd);

    snprintf(cmd,MAXBUF,"gpg --quiet --gen-key --expert --homedir=%s --batch %s",dir,keydetails);
    system(cmd);

    // read keyrings
    snprintf(keyring_name,MAXBUF,"%s/pubring.gpg", dir);
    ops_keyring_read(&pub_keyring,keyring_name);

    // read keyring
    snprintf(keyring_name,MAXBUF,"%s/secring.gpg", dir);
    ops_keyring_read(&sec_keyring,keyring_name);
#endif

    // Return success
    return 0;
    }

int clean_suite_crypto(void)
    {
#ifdef XXX
    /* Close OPS */
    
    ops_finish();
#endif
    reset_vars();

    return 0;
    }

static void test_cfb_aes256()
    {
    // Used for trying low-level OpenSSL tests

    ops_crypt_t crypt;
    ops_crypt_any(&crypt, OPS_SA_AES_256);

    /* 
       AES init
       using empty IV and key for the moment 
    */
    unsigned char *iv=ops_mallocz(crypt.blocksize);
    unsigned char *key=ops_mallocz(crypt.keysize);
    snprintf((char *)key, crypt.keysize, "AES_KEY");
    crypt.set_iv(&crypt, iv);
    crypt.set_key(&crypt, key);
    ops_encrypt_init(&crypt);

    unsigned char *in=ops_mallocz(crypt.blocksize);
    unsigned char *out=ops_mallocz(crypt.blocksize);
    unsigned char *out2=ops_mallocz(crypt.blocksize);

    snprintf((char *)in,crypt.blocksize,"hello");

    printf("\n");
    printf("in:\t0x%.2x 0x%.2x 0x%.2x 0x%.2x   0x%.2x 0x%.2x 0x%.2x 0x%.2x\n", 
           in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7]);
    printf("in:\t%c    %c    %c    %c      %c    %c    %c    %c\n", 
           in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7]);

    crypt.block_encrypt(&crypt, out, in);
    //        AES_ecb_encrypt(in,out,crypt.data,AES_ENCRYPT);

    printf("out:\t0x%.2x 0x%.2x 0x%.2x 0x%.2x   0x%.2x 0x%.2x 0x%.2x 0x%.2x\n", 
           out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]);
    printf("out:\t%c    %c    %c    %c      %c    %c    %c    %c\n", 
           out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]);


    crypt.block_decrypt(&crypt, out2, out);
    //        AES_ecb_encrypt(out,out2,crypt.data,AES_DECRYPT);
    printf("out2:\t0x%.2x 0x%.2x 0x%.2x 0x%.2x   0x%.2x 0x%.2x 0x%.2x 0x%.2x\n", 
           out2[0], out2[1], out2[2], out2[3], out2[4], out2[5], out2[6], out2[7]);
    printf("out2:\t%c    %c    %c    %c      %c    %c    %c    %c\n", 
           out2[0], out2[1], out2[2], out2[3], out2[4], out2[5], out2[6], out2[7]);

    CU_ASSERT(memcmp((char *)in, (char *)out2, strlen((char *)in))==0);

    }

static void test_cfb_cast()
    {
    // Used for trying low-level OpenSSL tests

    ops_crypt_t crypt;
    ops_crypt_any(&crypt, OPS_SA_CAST5);

    /*
     * CAST
     */
    unsigned char *iv=NULL;
    unsigned char *key=NULL;
    iv=ops_mallocz(crypt.blocksize);
    key=ops_mallocz(crypt.keysize);
    //    snprintf((char *)key, crypt_cast.keysize, "CAST_KEY");
    crypt.set_iv(&crypt, iv);
    crypt.set_key(&crypt, key);
    ops_encrypt_init(&crypt);

    unsigned char *in=ops_mallocz(crypt.blocksize);
    unsigned char *out=ops_mallocz(crypt.blocksize);
    unsigned char *out2=ops_mallocz(crypt.blocksize);

    snprintf((char *)in,crypt.blocksize,"hello");
	/*
    printf("\n");
    printf("in:\t0x%.2x 0x%.2x 0x%.2x 0x%.2x   0x%.2x 0x%.2x 0x%.2x 0x%.2x\n", 
           in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7]);
    printf("in:\t%c    %c    %c    %c      %c    %c    %c    %c\n", 
           in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7]);
	*/

    crypt.block_encrypt(&crypt, out, in);
    //    AES_ecb_encrypt(in,out,crypt.data,AES_ENCRYPT);
	/*
    printf("out:\t0x%.2x 0x%.2x 0x%.2x 0x%.2x   0x%.2x 0x%.2x 0x%.2x 0x%.2x\n", 
           out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]);
    printf("out:\t%c    %c    %c    %c      %c    %c    %c    %c\n", 
           out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]);
	*/

    crypt.block_decrypt(&crypt, out2, out);
    //    AES_ecb_encrypt(out,out2,crypt.data,AES_DECRYPT);
	/*
    printf("out2:\t0x%.2x 0x%.2x 0x%.2x 0x%.2x   0x%.2x 0x%.2x 0x%.2x 0x%.2x\n", 
           out2[0], out2[1], out2[2], out2[3], out2[4], out2[5], out2[6], out2[7]);
    printf("out2:\t%c    %c    %c    %c      %c    %c    %c    %c\n", 
           out2[0], out2[1], out2[2], out2[3], out2[4], out2[5], out2[6], out2[7]);
	*/
    CU_ASSERT(memcmp((char *)in, (char *)out2, strlen((char *)in))==0);

    }

static void test_rsa()
    {
    unsigned char* in=NULL;
    unsigned char* encrypted=NULL;
    unsigned char* decrypted=NULL;
    const ops_key_data_t *pub_key=NULL;
    const ops_public_key_t *pkey=NULL;
    const ops_key_data_t *sec_key=NULL;
    const ops_secret_key_t *skey=NULL;

    in=ops_mallocz(128);
    encrypted=ops_mallocz(128);
    decrypted=ops_mallocz(128);

    ops_random(in,128);

    int n=0;
    pub_key=ops_keyring_find_key_by_userid(&pub_keyring, alpha_user_id);
    //    ops_print_public_key(pub_key);
    pkey=ops_get_public_key_from_data(pub_key);

    sec_key=ops_keyring_find_key_by_userid(&sec_keyring, alpha_user_id);
    //    ops_print_secret_key(sec_key);
    skey=ops_get_secret_key_from_data(sec_key);

    /*
    unsigned int i;
    fprintf(stderr,"in:        ");
    for (i=0; i<128; i++)
        fprintf(stderr,"%2x ", in[i]);
    fprintf(stderr,"\n");
    */

    n=ops_rsa_public_encrypt(&encrypted[0], (unsigned char *)in, 128, &pkey->key.rsa);
    CU_ASSERT(n!=-1);
    if (n==-1)
        return;

    /*
    fprintf(stderr,"%d encrypted\n",n);
    fprintf(stderr,"encrypted: ");
    for (i=0; i<128; i++)
        fprintf(stderr,"%2x ", encrypted[i]);
    fprintf(stderr,"\n");
    */
    n=ops_rsa_private_decrypt(&decrypted[0], encrypted, 128,
                            &skey->key.rsa, &pkey->key.rsa);
    CU_ASSERT(n!=-1);
    if (n==-1)
        return;

    /*
    fprintf(stderr,"%d decrypted\n",n);
    fprintf(stderr,"decrypted: ");
    for (i=0; i<128; i++)
        fprintf(stderr,"%2x ", decrypted[i]);
    fprintf(stderr,"\n");
    */
    CU_ASSERT(memcmp(in,&decrypted[0],128)==0);

    //    fprintf(stderr,"memcmp returns %d\n",memcmp(in,&decrypted[0],128));

    free(encrypted);
    free(decrypted);
    }

CU_pSuite suite_crypto()
{
    CU_pSuite suite = NULL;

    suite = CU_add_suite("Crypto Suite", init_suite_crypto, clean_suite_crypto);
    if (!suite)
	    return NULL;

    // add tests to suite
    
    if (NULL == CU_add_test(suite, "Test CFB AES 256", test_cfb_aes256))
	    return NULL;

    if (NULL == CU_add_test(suite, "Test CFB CAST", test_cfb_cast))
	    return NULL;

    if (NULL == CU_add_test(suite, "Test RSA", test_rsa))
	    return NULL;

    return suite;
}

// EOF
