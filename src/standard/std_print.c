/*! \file
  \brief Standard API print functions
*/

/** @defgroup StdPrint Print
    \ingroup StandardAPI
*/

#include <assert.h>
#include "openpgpsdk/crypto.h"
#include "openpgpsdk/keyring.h"
#include "keyring_local.h"
#include "openpgpsdk/packet-show.h"
#include "openpgpsdk/util.h"
#include "openpgpsdk/std_print.h"

static int indent=0;

static void print_bn( const char *name, 
		      const BIGNUM *bn);
static void print_hex(const unsigned char *src,
		      size_t length);
static void print_hexdump(const char *name,
			  const unsigned char *data,
			  unsigned int len);
static void print_indent();
static void print_name(const char *name);
static void print_string_and_value(char *name,
				   const char *str,
				   unsigned char value);
static void print_tagname(const char *str);
static void print_time( char *name, 
			time_t time);
static void print_time_short(time_t time);
static void print_unsigned_int(char *name, 
			       unsigned int val);
static void showtime(const char *name,time_t t);
static void showtime_short(time_t t);

/**
   \ingroup StdPrintKeyring

   Prints a public key in succinct detail

   \param key Ptr to public key
*/

void 
ops_print_public_key(const ops_key_data_t *key)
    {
    printf("pub ");

    ops_show_pka(key->key.pkey.algorithm);
    printf(" ");

    hexdump(key->keyid, OPS_KEY_ID_SIZE);
    printf(" ");

    print_time_short(key->key.pkey.creation_time);
    printf(" ");

    if (key->nuids==1)
	{
	// print on same line as other info
	printf ("%s\n", key->uids[0].user_id);
	}
    else
	{
	// print all uids on separate line 
	unsigned int i;
	printf("\n");
	for (i=0; i<key->nuids; i++)
	    {
	    printf("uid                              %s\n",key->uids[i].user_id);
	    }
	}
    }

/**
   \ingroup StdPrintKeyring

   Prints a public key in full detail

   \param key Ptr to public key
*/

void 
ops_print_public_key_verbose(const ops_key_data_t *key)
    {
    const ops_public_key_t* pkey=&key->key.pkey;

    print_unsigned_int("Version",pkey->version);
    print_time("Creation Time", pkey->creation_time);
    if(pkey->version == OPS_V3)
	print_unsigned_int("Days Valid",pkey->days_valid);

    print_string_and_value("Algorithm",ops_show_pka(pkey->algorithm),
			   pkey->algorithm);

    switch(pkey->algorithm)
	{
    case OPS_PKA_DSA:
	print_bn("p",pkey->key.dsa.p);
	print_bn("q",pkey->key.dsa.q);
	print_bn("g",pkey->key.dsa.g);
	print_bn("y",pkey->key.dsa.y);
	break;

    case OPS_PKA_RSA:
    case OPS_PKA_RSA_ENCRYPT_ONLY:
    case OPS_PKA_RSA_SIGN_ONLY:
	print_bn("n",pkey->key.rsa.n);
	print_bn("e",pkey->key.rsa.e);
	break;

    case OPS_PKA_ELGAMAL:
    case OPS_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
	print_bn("p",pkey->key.elgamal.p);
	print_bn("g",pkey->key.elgamal.g);
	print_bn("y",pkey->key.elgamal.y);
	break;

    default:
	assert(0);
	}
    }

/**
   \ingroup StdPrintKeyring

   Prints a secret key

   \param key Ptr to public key
*/

void 
ops_print_secret_key(const ops_key_data_t* key)
    {
    const ops_secret_key_t* skey=&key->key.skey;
    if(key->type == OPS_PTAG_CT_SECRET_KEY)
	print_tagname("SECRET_KEY");
    else
	print_tagname("ENCRYPTED_SECRET_KEY");
    ops_print_public_key(key);
    printf("S2K Usage: %d\n",skey->s2k_usage);
    if(skey->s2k_usage != OPS_S2KU_NONE)
	{
	printf("S2K Specifier: %d\n",skey->s2k_specifier);
	printf("Symmetric algorithm: %d (%s)\n",skey->algorithm,
	       ops_show_symmetric_algorithm(skey->algorithm));
	printf("Hash algorithm: %d (%s)\n",skey->hash_algorithm,
	       ops_show_hash_algorithm(skey->hash_algorithm));
	if(skey->s2k_specifier != OPS_S2KS_SIMPLE)
	    print_hexdump("Salt",skey->salt,sizeof skey->salt);
	if(skey->s2k_specifier == OPS_S2KS_ITERATED_AND_SALTED)
	    printf("Octet count: %d\n",skey->octet_count);
	print_hexdump("IV",skey->iv,ops_block_size(skey->algorithm));
	}

    /* no more set if encrypted */
    if(key->type == OPS_PTAG_CT_ENCRYPTED_SECRET_KEY)
	return;

    switch(skey->public_key.algorithm)
	{
    case OPS_PKA_RSA:
	print_bn("d",skey->key.rsa.d);
	print_bn("p",skey->key.rsa.p);
	print_bn("q",skey->key.rsa.q);
	print_bn("u",skey->key.rsa.u);
	break;

    case OPS_PKA_DSA:
	print_bn("x",skey->key.dsa.x);
	break;

    default:
	assert(0);
	}

    if(skey->s2k_usage == OPS_S2KU_ENCRYPTED_AND_HASHED)
	print_hexdump("Checkhash",skey->checkhash,OPS_CHECKHASH_SIZE);
    else
	printf("Checksum: %04x\n",skey->checksum);
    }

// static functions

static void print_unsigned_int(char *name, unsigned int val)
    {
    print_name(name);
    printf("%d\n", val);
    }

static void print_time( char *name, time_t time)
    {
    print_indent();
    printf("%s: ",name);
    showtime("time",time);
    printf("\n");
    }

static void print_time_short(time_t time)
    {
    showtime_short(time);
    }

static void print_string_and_value(char *name,const char *str,
				   unsigned char value)
    {
    print_name(name);

    printf("%s", str);
    printf(" (0x%x)", value);
    printf("\n");
    }

static void print_bn( const char *name, const BIGNUM *bn)
    {
    print_indent();
    printf("%s=",name);
    if(bn)
	{
	BN_print_fp(stdout,bn);
	putchar('\n');
	}
    else
	puts("(unset)");
    }

static void print_tagname(const char *str)
    {
    print_indent();
    printf("%s packet\n", str);
    }

static void print_hexdump(const char *name,
			  const unsigned char *data,
			  unsigned int len)
    {
    print_name(name);

    printf("len=%d, data=0x", len);
    print_hex(data,len);
    printf("\n");
    }

static void print_name(const char *name)
    {
    print_indent();
    if(name)
	printf("%s: ",name);
    }

static void print_indent()
    {
    int i=0;

    for(i=0 ; i < indent ; i++)
	printf("  ");
    }

/* printhex is now print_hex for consistency */
static void print_hex(const unsigned char *src,size_t length)
    {
    while(length--)
	printf("%02X",*src++);
    }

static void showtime(const char *name,time_t t)
    {
    printf("%s=" TIME_T_FMT " (%.24s)",name,t,ctime(&t));
    }
static void showtime_short(time_t t)
    {
    struct tm* tm;
    /*
    const int maxbuf=512;
    char buf[maxbuf+1];
    buf[maxbuf]='\0';
    // this needs to be tm struct
    strftime(buf,maxbuf,"%F",&t);
    printf(buf);
    */
    tm=gmtime(&t);
    printf ("%04d-%02d-%02d", tm->tm_year+1900, tm->tm_mon, tm->tm_mday);
    }


