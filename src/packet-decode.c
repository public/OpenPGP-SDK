/** \file packet-decode.c
 *
 * Creates printable text strings from packet contents
 *
 * $Id$
 */

#include "packet-decode.h"

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

octet_map_t symmetric_key_algorithm_map[] =
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

bit_map_t ss_feature_map_byte0[] =
    {
    { 0x01,	"Modification Detection" },
    { (unsigned char) NULL,	(char *) NULL },
    };

bit_map_t * ss_feature_map[] =
    {
    ss_feature_map_byte0,
    (bit_map_t *) NULL,
    };

bit_map_t ss_key_flags_map[] =
    {
    { 0x01, "May be used to certify other keys" },
    { 0x02, "May be used to sign data" },
    { 0x04, "May be used to encrypt communications" },
    { 0x08, "May be used to encrypt storage" },
    { 0x10, "Private component may have been split by a secret-sharing mechanism"},
    { 0x80, "Private component may be in possession of more than one person"},
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

static char * search_octet_map(unsigned char octet, octet_map_t * map)
    {
    octet_map_t * row;

    for ( row=map; row->string != NULL; row++ )
	if (row->type == octet) 
	    return row->string;

    return NULL;
    }

static char * search_bit_map(unsigned char octet, bit_map_t *map)
    {
    bit_map_t * row;

    for ( row=map; row->string != NULL; row++ )
	if (row->mask == octet) 
	    return row->string;

    return NULL;
    }


unsigned int process_octet_str(decoded_t * decoded, char * str, unsigned char octet)
    {
    if (str && !add_str(&decoded->known,str)) 
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
	sprintf(str,"Unknown(%d)",octet);
	if (!add_str(&decoded->unknown,str))
	    return 0;
	}
    return 1;
    }

unsigned int process_bitmap_str(decoded_t * decoded, char * str, unsigned char bit)
    {
    if (str && !add_str(&decoded->known,str)) 
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
	if (!add_str(&decoded->unknown,str))
	    return 0;
	}
    return 1;
    }

/*
 * Public Functions
 */

void decoded_init(decoded_t * decoded)
    {
    list_init(&decoded->known);
    list_init(&decoded->unknown);
    }

void decoded_free(decoded_t * decoded)
    {
    /* Strings in "known" array will be constants, so don't free them */
    list_free(&decoded->known);

    /* Strings in "unknown" array will be dynamically allocated, so do free them */
    list_free_strings(&decoded->unknown);
    list_free(&decoded->unknown);

    /* finally, free the decoded structure itself */
    free(decoded);
    }

/*
 * Now the individual decode functions
 */

char * decode_single_ss_preferred_ska(unsigned char octet)
    {
    return(search_octet_map(octet,symmetric_key_algorithm_map));
    }

decoded_t * decode_ss_preferred_ska(ops_ss_preferred_ska_t array)
    {
    /* this can be generalised further to handle any similar list -- rachel */

    decoded_t * decoded=NULL;
    char * str;
    int i=0;

    decoded=malloc(sizeof(decoded_t));
    if (!decoded)
	return NULL;

    decoded_init(decoded);

    for ( i=0; i < array.len; i++)
	{
	str=decode_single_ss_preferred_ska(array.data[i]);
	if (!process_octet_str(decoded,str,array.data[i]))
	    return NULL;

	}
    /* All values have been added to either the known or the unknown list */
    return decoded;
    }

char * decode_single_ss_feature(unsigned char octet, bit_map_t * map)
    {
    return(search_bit_map(octet,map));
    }

/** decoded_t * decode_ss_features(ops_ss_features_t * ss_features)
*/

decoded_t * decode_ss_features(ops_ss_features_t ss_features)
    {
    decoded_t *decoded=NULL;
    char *str;
    int i=0, j=0;
    unsigned char mask, bit;

     decoded=malloc(sizeof(decoded_t));
    if (!decoded)
	return NULL;

    decoded_init(decoded);

    for ( i=0; i < ss_features.len; i++)
	{
	for (j=0, mask=0x80; j<8; j++, mask = mask>>1 )
	    {
	    bit = ss_features.data[i]&mask;
	    if (bit)
		{
		str=decode_single_ss_feature ( bit, ss_feature_map[i] );
		if (!process_bitmap_str( decoded, str, bit))
		    return NULL;
		}
	    }
	}
    return decoded;
    }

char * decode_single_ss_key_flag(unsigned char octet, bit_map_t * map)
    {
    return(search_bit_map(octet,map));
    }

decoded_t * decode_ss_key_flags(ops_ss_key_flags_t ss_key_flags)
    {
    decoded_t *decoded=NULL;
    char *str;
    int i=0;
    unsigned char mask, bit;

     decoded=malloc(sizeof(decoded_t));
    if (!decoded)
	return NULL;

    decoded_init(decoded);

    /* xxx - TBD: extend to handle multiple octets of bits - rachel */

    for (i=0, mask=0x80; i<8; i++, mask = mask>>1 )
	    {
	    bit = ss_key_flags.data[0] & mask;
	    if (bit)
		{
		str=decode_single_ss_key_flag ( bit, &ss_key_flags_map[0] );
		if (!process_bitmap_str( decoded, str, bit))
		    return NULL;
		}
	    }
/* xxx - must add error text if more than one octet. Only one currently specified -- rachel */
    return decoded;
    }

/* end of file */
