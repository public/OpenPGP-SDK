#include <time.h>
#include <openssl/bn.h>

/* PTag (4.2) */

#define OPS_PTAG_ALWAYS_SET		0x80
#define OPS_PTAG_NEW_FORMAT		0x40

/* PTag Old Format */

#define OPS_PTAG_OF_CONTENT_TAG_MASK	0x3c
#define OPS_PTAG_OF_CONTENT_TAG_SHIFT	2
#define OPS_PTAG_OF_LENGTH_TYPE_MASK	0x03

/* PTag Old Format Length Types */

typedef enum
    {
    OPS_PTAG_OF_LT_ONE_BYTE		=0x00,
    OPS_PTAG_OF_LT_TWO_BYTE		=0x01,
    OPS_PTAG_OF_LT_FOUR_BYTE		=0x02,
    OPS_PTAG_OF_LT_INDETERMINATE	=0x03,
    } ops_ptag_of_lt;

/* PTag New Format */

#define OPS_PTAG_NF_CONTENT_TAG_MASK	0x3f
#define OPS_PTAG_NF_CONTENT_TAG_SHIFT	0

/* PTag Content Tags (4.3) */
/* AKA Packet Tags */

typedef enum
    {
    OPS_PTAG_CT_RESERVED		=0x00,
    OPS_PTAG_CT_PK_SESSION_KEY		=0x01,
    OPS_PTAG_CT_SIGNATURE		=0x02,
    OPS_PTAG_CT_SK_SESSION_KEY		=0x03,
    OPS_PTAG_CT_ONE_PASS_SIGNATURE	=0x04,
    OPS_PTAG_CT_SECRET_KEY		=0x05,
    OPS_PTAG_CT_PUBLIC_KEY		=0x06,
    OPS_PTAG_CT_SECRET_SUBKEY		=0x07,
    OPS_PTAG_CT_COMPRESSED		=0x08,
    OPS_PTAG_CT_SK_DATA			=0x09,
    OPS_PTAG_CT_MARKER			=0x0a,
    OPS_PTAG_CT_LITERAL_DATA		=0x0b,
    OPS_PTAG_CT_TRUST			=0x0c,
    OPS_PTAG_CT_USER_ID			=0x0d,
    OPS_PTAG_CT_PUBLIC_SUBKEY		=0x0e,
    OPS_PTAG_CT_RESERVED2		=0x0f,
    OPS_PTAG_CT_RESERVED3		=0x10,
    OPS_PTAG_CT_USER_ATTRIBUTE		=0x11,
    OPS_PTAG_CT_SK_IP_DATA		=0x12,
    OPS_PTAG_CT_MDC			=0x13,

    /* used by the parser */
    OPS_PARSER_ERROR			=0x100,
    OPS_PARSER_PTAG			=0x101,
    } ops_content_tag;

typedef struct
    {
    const char *error;
    } ops_parser_error;

typedef struct
    {
    unsigned new_format;
    unsigned content_tag;
    ops_ptag_of_lt length_type; /* only if new_format not set */
    unsigned length;
    unsigned length_read; /* internal use only */
    } ops_parser_ptag;

typedef enum
    {
    OPS_PKA_RSA			=1,
    OPS_PKA_RSA_ENCRYPT_ONLY	=2,
    OPS_PKA_RSA_SIGN_ONLY	=3,
    OPS_PKA_ELGAMEL		=16,
    OPS_PKA_DSA			=17
    } ops_public_key_algorithm;

typedef struct
    {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
    BIGNUM *y;
    } ops_dsa_public_key;

typedef struct
    {
    BIGNUM *n;
    BIGNUM *e;
    } ops_rsa_public_key;

typedef union
    {
    ops_dsa_public_key dsa;
    ops_rsa_public_key rsa;
    } ops_public_key;

typedef struct
    {
    unsigned 			version;
    time_t			creation_time;
    unsigned			days_valid; /* 0 means forever */
    ops_public_key_algorithm	algorithm;
    ops_public_key		key;
    } ops_parser_public_key;

typedef union
    {
    ops_parser_error		error;
    ops_parser_ptag		ptag;
    ops_parser_public_key	public_key;
    } ops_parser_content;
