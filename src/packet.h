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
    } ops_ptag_of_lt_t;

/* PTag New Format */

#define OPS_PTAG_NF_CONTENT_TAG_MASK	0x3f
#define OPS_PTAG_NF_CONTENT_TAG_SHIFT	0

/* PTag Content Tags (4.3) */
/* AKA Packet Tags */

typedef enum
    {
    OPS_PTAG_CT_RESERVED		=0,
    OPS_PTAG_CT_PK_SESSION_KEY		=1,
    OPS_PTAG_CT_SIGNATURE		=2,
    OPS_PTAG_CT_SK_SESSION_KEY		=3,
    OPS_PTAG_CT_ONE_PASS_SIGNATURE	=4,
    OPS_PTAG_CT_SECRET_KEY		=5,
    OPS_PTAG_CT_PUBLIC_KEY		=6,
    OPS_PTAG_CT_SECRET_SUBKEY		=7,
    OPS_PTAG_CT_COMPRESSED		=8,
    OPS_PTAG_CT_SK_DATA			=9,
    OPS_PTAG_CT_MARKER			=10,
    OPS_PTAG_CT_LITERAL_DATA		=11,
    OPS_PTAG_CT_TRUST			=12,
    OPS_PTAG_CT_USER_ID			=13,
    OPS_PTAG_CT_PUBLIC_SUBKEY		=14,
    OPS_PTAG_CT_RESERVED2		=15,
    OPS_PTAG_CT_RESERVED3		=16,
    OPS_PTAG_CT_USER_ATTRIBUTE		=17,
    OPS_PTAG_CT_SK_IP_DATA		=18,
    OPS_PTAG_CT_MDC			=19,

    /* used by the parser */
    OPS_PARSER_ERROR			=0x100,
    OPS_PARSER_PTAG			=0x101,
    } ops_content_tag_t;

typedef struct
    {
    const char *error;
    } ops_parser_error_t;

typedef struct
    {
    unsigned		new_format;
    unsigned		content_tag;
    ops_ptag_of_lt_t	length_type; /* only if new_format not set */
    unsigned		length;
    unsigned		length_read; /* internal use only */
    } ops_ptag_t;

typedef enum
    {
    OPS_PKA_RSA			=1,
    OPS_PKA_RSA_ENCRYPT_ONLY	=2,
    OPS_PKA_RSA_SIGN_ONLY	=3,
    OPS_PKA_ELGAMEL		=16,
    OPS_PKA_DSA			=17
    } ops_public_key_algorithm_t;

typedef struct
    {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
    BIGNUM *y;
    } ops_dsa_public_key_t;

typedef struct
    {
    BIGNUM *n;
    BIGNUM *e;
    } ops_rsa_public_key_t;

typedef union
    {
    ops_dsa_public_key_t	dsa;
    ops_rsa_public_key_t	rsa;
    } ops_public_key_union_t;

typedef struct
    {
    unsigned 			version;
    time_t			creation_time;
    unsigned			days_valid; /* 0 means forever */
    ops_public_key_algorithm_t	algorithm;
    ops_public_key_union_t	key;
    } ops_public_key_t;

typedef struct
    {
    char *			user_id;
    } ops_user_id_t;

typedef union
    {
    ops_parser_error_t		error;
    ops_ptag_t			ptag;
    ops_public_key_t		public_key;
    ops_user_id_t		user_id;
    } ops_parser_content_union_t;

typedef struct
    {
    ops_content_tag_t		tag;
    ops_parser_content_union_t 	content;
    } ops_parser_content_t;

