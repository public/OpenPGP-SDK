/** \file 
 *
 * Creates printable text strings from packet contents
 *
 */

#include "packet-to-text.h"

#include <stdlib.h>
#include <string.h>

#ifdef DMALLOC
# include <dmalloc.h>
#endif

/*
 * 
 * Structures specific to this file
 *
 */

typedef struct 
    {
    int type;
    char * string;
    } octet_map_t;

/*
 * Arrays of value->text maps
 */

static octet_map_t revocation_reason_code_map[] =
    {
    { 0x00,	"No reason specified" },
    { 0x01,	"Key is superseded" },
    { 0x02,	"Key material has been compromised" },
    { 0x03,	"Key is retired and no longer used" },
    { 0x20,	"User ID information is no longer valid" },
    { (int) NULL,		(char *)NULL }, /* this is the end-of-array marker */
    };

static octet_map_t symmetric_key_algorithm_map[] =
    {
    { OPS_SKA_PLAINTEXT,	"Plaintext or unencrypted data" },
    { OPS_SKA_IDEA,		"IDEA" },
    { OPS_SKA_TRIPLEDES,	"TripleDES" },
    { OPS_SKA_CAST5,		"CAST5" },
    { OPS_SKA_BLOWFISH,		"Blowfish" },
    { OPS_SKA_AES_128,		"AES(128-bit key)" },
    { OPS_SKA_AES_192,		"AES(192-bit key)" },
    { OPS_SKA_AES_256, 		"AES(256-bit key)" },
    { OPS_SKA_TWOFISH, 		"Twofish(256-bit key)" },
    { (int) NULL,		(char *)NULL }, /* this is the end-of-array marker */
    };

static octet_map_t hash_algorithm_map[] =
    {
    { OPS_HASH_MD5,	"MD5" },
    { OPS_HASH_SHA1,	"SHA1" },
    { OPS_HASH_RIPEMD,	"RIPEMD160" },
    { OPS_HASH_SHA256,	"SHA256" },
    { OPS_HASH_SHA384,	"SHA384" },
    { OPS_HASH_SHA512,	"SHA512" },
    { (int) NULL,		(char *)NULL }, /* this is the end-of-array marker */
    };

static octet_map_t compression_algorithm_map[] =
    {
    { OPS_C_NONE,	"Uncompressed" },
    { OPS_C_ZIP,	"ZIP(RFC1951)" },
    { OPS_C_ZLIB,	"ZLIB(RFC1950)" },
    { OPS_C_BZIP2,	"Bzip2(BZ2)" },
    { (int) NULL,		(char *)NULL }, /* this is the end-of-array marker */
    };

static bit_map_t ss_notation_data_map_byte0[] =
    {
    { 0x80,	"Human-readable" },
    { (unsigned char) NULL,	(char *) NULL },
    };

static bit_map_t * ss_notation_data_map[] =
    {
    ss_notation_data_map_byte0,
    (bit_map_t *) NULL,
    };

static bit_map_t ss_feature_map_byte0[] =
    {
    { 0x01,	"Modification Detection" },
    { (unsigned char) NULL,	(char *) NULL },
    };

static bit_map_t * ss_feature_map[] =
    {
    ss_feature_map_byte0,
    (bit_map_t *) NULL,
    };

static bit_map_t ss_key_flags_map[] =
    {
    { 0x01, "May be used to certify other keys" },
    { 0x02, "May be used to sign data" },
    { 0x04, "May be used to encrypt communications" },
    { 0x08, "May be used to encrypt storage" },
    { 0x10, "Private component may have been split by a secret-sharing mechanism"},
    { 0x80, "Private component may be in possession of more than one person"},
    };

static bit_map_t ss_key_server_prefs_map[] = 
    {
    { 0x80, "Key holder requests that this key only be modified or updated\nby the key holder or an administrator of the key server" },
    };

/*
 * Private functions
 */

static void list_init(list_t *list)
    {
    list->size=0;
    list->used=0;
    list->strings=NULL;
    }
 
static void list_free_strings(list_t * list)
    {
    int i=0;

    for ( i=0; i < list->used; i++)
	{
	free(list->strings[i]);
	list->strings[i]=NULL;
	}
    }

static void list_free(list_t * list)
    {
    if (list->strings)
	free(list->strings);
    list_init(list);
    }

static unsigned int list_resize(list_t * list)
    {
    /* We only resize in one direction - upwards.
       Algorithm used : double the current size then add 1
    */

    int newsize=0;

    newsize=list->size*2 + 1;
    list->strings=realloc(list->strings,newsize*sizeof(char *));
    if (list->strings)
	{
	list->size=newsize;
	return 1;
	}
    else
	{
	/* xxx - realloc failed. error message? - rachel */
	return 0;
	}
    }

static unsigned int add_str(list_t * list, char * str)
    {
    if (list->size==list->used) 
	if (!list_resize(list))
	    return 0;

    list->strings[list->used]=str;
    list->used++;
    return 1;
    }

static char * str_from_octet_map(unsigned char octet, octet_map_t * map)
    {
    octet_map_t * row;

    for ( row=map; row->string != NULL; row++ )
	if (row->type == octet) 
	    return row->string;

    return NULL;
    }

static char * str_from_bitfield(unsigned char octet, bit_map_t *map)
    {
    bit_map_t * row;

    for ( row=map; row->string != NULL; row++ )
	if (row->mask == octet) 
	    return row->string;

    return NULL;
    }

/*! generic function to initialise text_t structure */
void text_init(text_t * text)
    {
    list_init(&text->known);
    list_init(&text->unknown);
    }

/*! generic function to free memory used by text_t structure */
void text_free(text_t * text)
    {
    /* Strings in "known" array will be constants, so don't free them */
    list_free(&text->known);

    /* Strings in "unknown" array will be dynamically allocated, so do free them */
    list_free_strings(&text->unknown);
    list_free(&text->unknown);

    /* finally, free the text structure itself */
    free(text);
    }

/*! generic function which adds text derived from single octet map to text */
static unsigned int add_str_from_octet_map(text_t * text, char * str, unsigned char octet)
    {
    if (str && !add_str(&text->known,str)) 
	{
	/* value recognised, but there was a problem adding it to the list */
	/* XXX - should print out error msg here, Ben? - rachel */
	return 0;
	}
    else if (!str)
	{
	/* value not recognised and there was a problem adding it to the unknown list */

#define MAXSTR 255
	str=malloc(MAXSTR+1);
	/* xxx - This isn't very nice, how do you ensure the string isn't overrun.
	   Ben? -- rachel */
	sprintf(str,"0x%x",octet);
	if (!add_str(&text->unknown,str))
	    return 0;
	}
    return 1;
    }

/*! generic function which adds text derived from single bit map to text */
static unsigned int add_str_from_bit_map(text_t * text, char * str, unsigned char bit)
    {
    if (str && !add_str(&text->known,str)) 
	{
	/* value recognised, but there was a problem adding it to the list */
	/* XXX - should print out error msg here, Ben? - rachel */
	return 0;
	}
    else if (!str)
	{
	/* value not recognised and there was a problem adding it to the unknown list */

#define MAXSTR 255
	str=malloc(MAXSTR+1);
	/* xxx - This isn't very nice, how do you ensure the string isn't overrun.
	   Ben? -- rachel */
	sprintf(str,"Unknown bit(%d)",bit);
	if (!add_str(&text->unknown,str))
	    return 0;
	}
    return 1;
    }

/**
 * Produce a structure containing human-readable textstrings
 * representing the recognised and unrecognised contents
 * of this byte array. text_fn() will be called on each octet in turn.
 *
 */ 

static text_t *text_from_octets(data_t *data, 
			      char *(*text_fn)(unsigned char octet))
    {

    text_t * text=NULL;
    char * str;
    int i=0;

    /*! allocate and initialise text_t structure to store derived strings */
    text=malloc(sizeof(text_t));
    if (!text)
	return NULL;

    text_init(text);

    /*! for each octet in field ... */
    for ( i=0; i < data->len; i++)
	{
	/*! derive string from octet */
	str=(*text_fn)(data->contents[i]);

	/*! and add to text */
	if (!add_str_from_octet_map(text,str,data->contents[i]))
	    return NULL;

	}
    /*! All values have been added to either the known or the unknown list */
    /*! Return text */
    return text;
    }

/**
 * Produce a structure containing human-readable textstrings
 * representing the recognised and unrecognised contents
 * of this byte array, derived from each bit of each octet.
 *
 */ 
static text_t * text_from_octets_bits(data_t *data, bit_map_t **map)
    {
    text_t *text=NULL;
    char *str;
    int i=0, j=0;
    unsigned char mask, bit;

    /*! allocate and initialise text_t structure to store derived strings */
     text=malloc(sizeof(text_t));
    if (!text)
	return NULL;

    text_init(text);

    /*! for each octet in field ... */
    for ( i=0; i < data->len; i++)
	{
	/*! for each bit in octet ... */
	for (j=0, mask=0x80; j<8; j++, mask = mask>>1 )
	    {
	    bit = data->contents[i]&mask;
	    if (bit)
		{
		/*! if bit is set, then derive string from it */
		str=str_from_bitfield ( bit, map[i] );
		if (!add_str_from_bit_map( text, str, bit))
		    return NULL;
		}
	    }
	}
    return text;
    }

/*
 * Public Functions
 */

/*! returns string derived from this signature sub-packet type */
char * str_from_ss_revocation_reason_code(unsigned char octet)
    {
    return(str_from_octet_map(octet,revocation_reason_code_map));
    }

/*! returns string derived from a single octet in this field */
char * str_from_single_ss_preferred_compression(unsigned char octet)
    {
    return(str_from_octet_map(octet,compression_algorithm_map));
    }

/*! returns all text derived from this signature sub-packet type */
text_t * text_from_ss_preferred_compression(ops_ss_preferred_compression_t array)
    {
    return(text_from_octets(&array.data,
			  &str_from_single_ss_preferred_compression));
    }


/*! returns string derived from a single octet in this field */
char * str_from_single_ss_preferred_hash(unsigned char octet)
    {
    return(str_from_octet_map(octet,hash_algorithm_map));
    }

/*! returns all text derived from this signature sub-packet type */
text_t * text_from_ss_preferred_hash(ops_ss_preferred_hash_t array)
    {
    return(text_from_octets(&array.data,
			  &str_from_single_ss_preferred_hash));
    }

/*! returns string derived from a single octet in this field */
char * str_from_single_ss_preferred_ska(unsigned char octet)
    {
    return(str_from_octet_map(octet,symmetric_key_algorithm_map));
    }

/*! returns all text derived from this signature sub-packet type */
text_t * text_from_ss_preferred_ska(ops_ss_preferred_ska_t ss_preferred_ska)
    {
    return(text_from_octets(&ss_preferred_ska.data, 
		       &str_from_single_ss_preferred_ska));
    }

/*! returns string derived from one bitfield in this signature-subpacket type */
char * str_from_single_ss_feature(unsigned char octet, bit_map_t * map)
    {
    return(str_from_bitfield(octet,map));
    }

/*! returns all text derived from this signature sub-packet type */
text_t * text_from_ss_features(ops_ss_features_t ss_features)
    {
    text_t *text=NULL;
    char *str;
    int i=0, j=0;
    unsigned char mask, bit;

     text=malloc(sizeof(text_t));
    if (!text)
	return NULL;

    text_init(text);

    for ( i=0; i < ss_features.data.len; i++)
	{
	for (j=0, mask=0x80; j<8; j++, mask = mask>>1 )
	    {
	    bit = ss_features.data.contents[i]&mask;
	    if (bit)
		{
		str=str_from_single_ss_feature ( bit, ss_feature_map[i] );
		if (!add_str_from_bit_map( text, str, bit))
		    return NULL;
		}
	    }
	}
    return text;
    }

/*! returns all text derived from this signature sub-packet type */
text_t * text_from_ss_notation_data_flags(ops_ss_notation_data_t ss_notation_data)
    {
    return(text_from_octets_bits(&ss_notation_data.flags,ss_notation_data_map));
    }

/*! returns string derived from one bitfield in this signature-subpacket type */
char * str_from_single_ss_key_flag(unsigned char octet, bit_map_t * map)
    {
    return(str_from_bitfield(octet,map));
    }

/*! returns all text derived from this signature sub-packet type */
text_t * text_from_ss_key_flags(ops_ss_key_flags_t ss_key_flags)
    {
    text_t *text=NULL;
    char *str;
    int i=0;
    unsigned char mask, bit;

     text=malloc(sizeof(text_t));
    if (!text)
	return NULL;

    text_init(text);

    /* xxx - TBD: extend to handle multiple octets of bits - rachel */

    for (i=0, mask=0x80; i<8; i++, mask = mask>>1 )
	    {
	    bit = ss_key_flags.data.contents[0] & mask;
	    if (bit)
		{
		str=str_from_single_ss_key_flag ( bit, &ss_key_flags_map[0] );
		if (!add_str_from_bit_map( text, str, bit))
		    return NULL;
		}
	    }
/* xxx - must add error text if more than one octet. Only one currently specified -- rachel */
    return text;
    }

/*! returns string derived from one bitfield in this signature-subpacket type */
char *str_from_single_ss_key_server_prefs(unsigned char octet, bit_map_t *map)
    {
    return(str_from_bitfield(octet,map));
    }

/*! returns all text derived from this signature sub-packet type */
text_t *text_from_ss_key_server_prefs(ops_ss_key_server_prefs_t ss_key_server_prefs)
    {
    text_t *text=NULL;
    char *str;
    int i=0;
    unsigned char mask, bit;

    text=malloc(sizeof(text_t));
    if (!text)
	return NULL;

    text_init(text);

    /* xxx - TBD: extend to handle multiple octets of bits - rachel */

    for (i=0, mask=0x80; i<8; i++, mask = mask>>1 )
	    {
	    bit = ss_key_server_prefs.data.contents[0] & mask;
	    if (bit)
		{
		str=str_from_single_ss_key_server_prefs ( bit, &ss_key_server_prefs_map[0] );
		if (!add_str_from_bit_map( text, str, bit))
		    return NULL;
		}
	    }
/* xxx - must add error text if more than one octet. Only one currently specified -- rachel */
    return text;
    }

/* end of file */

