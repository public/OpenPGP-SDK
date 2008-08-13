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

/** \file
 * \brief Code for dealing with ASCII-armoured packets
 */

#include <openpgpsdk/callback.h>
#include <openpgpsdk/configure.h>
#include <openpgpsdk/armour.h>
#include <openpgpsdk/util.h>
#include <openpgpsdk/crypto.h>
#include <openpgpsdk/create.h>
#include <openpgpsdk/readerwriter.h>
#include <openpgpsdk/signature.h>
#include <openpgpsdk/version.h>
#include <openpgpsdk/packet-parse.h>

#include <string.h>
#include <assert.h>

#include <openpgpsdk/final.h>

//static int debug=0;

#define CRC24_POLY 0x1864cfbL

/**
 * \struct dearmour_arg_t
 */
typedef struct
    {
    enum
	{
	OUTSIDE_BLOCK=0,
	BASE64,
	AT_TRAILER_NAME,
	} state;
    ops_parse_info_t *parse_info;
    ops_boolean_t seen_nl:1;
    ops_boolean_t prev_nl:1;
    ops_boolean_t allow_headers_without_gap:1; /*!< allow headers in
						  armoured data that
						  are not separated
						  from the data by a
						  blank line */
    ops_boolean_t allow_no_gap:1; /*!< allow no blank line at the
				       start of armoured data */
    ops_boolean_t allow_trailing_whitespace:1; /*!< allow armoured
						 stuff to have
						 trailing whitespace
						 where we wouldn't
						 strictly expect it */

    // base64 stuff
    unsigned buffered;
    unsigned char buffer[3];
    ops_boolean_t eof64;
    unsigned long checksum;
    unsigned long read_checksum;
    // unarmoured text blocks
    unsigned char unarmoured[8192];
    size_t num_unarmoured;
    // pushed back data (stored backwards)
    unsigned char *pushed_back;
    unsigned npushed_back;
    // armoured block headers
    ops_headers_t headers;
    } dearmour_arg_t;

static void push_back(dearmour_arg_t *arg,const unsigned char *buf,
		      unsigned length)
    {
    unsigned n;

    assert(!arg->pushed_back);
    arg->pushed_back=malloc(length);
    for(n=0 ; n < length ; ++n)
	arg->pushed_back[n]=buf[length-n-1];
    arg->npushed_back=length;
    }
    
static int read_char(dearmour_arg_t *arg,ops_error_t **errors,
		     ops_reader_info_t *rinfo,
		     ops_parse_cb_info_t *cbinfo,
		     ops_boolean_t skip)
    {
    unsigned char c[1];

    do
	{
	if(arg->npushed_back)
	    {
	    c[0]=arg->pushed_back[--arg->npushed_back];
	    if(!arg->npushed_back)
		{
		free(arg->pushed_back);
		arg->pushed_back=NULL;
		}
	    }
	/* XXX: should ops_stacked_read exist? Shouldn't this be a limited_read? */
	else if(ops_stacked_read(c,1,errors,rinfo,cbinfo) != 1)
	    return -1;
	}
    while(skip && c[0] == '\r');

    arg->prev_nl=arg->seen_nl;
    arg->seen_nl=c[0] == '\n';

    return c[0];
    }

static int eat_whitespace(int first,
			  dearmour_arg_t *arg,ops_error_t **errors,
			  ops_reader_info_t *rinfo,
			  ops_parse_cb_info_t *cbinfo,
			  ops_boolean_t skip)
    {
    int c=first;

    while(c == ' ' || c == '\t')
	c=read_char(arg,errors,rinfo,cbinfo,skip);

    return c;
    }

static int read_and_eat_whitespace(dearmour_arg_t *arg,
				   ops_error_t **errors,
				   ops_reader_info_t *rinfo,
				   ops_parse_cb_info_t *cbinfo,
				   ops_boolean_t skip)
    {
    int c;

    do
	c=read_char(arg,errors,rinfo,cbinfo,skip);
    while(c == ' ' || c == '\t');

    return c;
    }

static void flush(dearmour_arg_t *arg,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_t content;

    if(arg->num_unarmoured == 0)
	return;

    content.content.unarmoured_text.data=arg->unarmoured;
    content.content.unarmoured_text.length=arg->num_unarmoured;
    CB(cbinfo,OPS_PTAG_CT_UNARMOURED_TEXT,&content);
    arg->num_unarmoured=0;
    }

static int unarmoured_read_char(dearmour_arg_t *arg,ops_error_t **errors,
				ops_reader_info_t *rinfo,
				ops_parse_cb_info_t *cbinfo,
				ops_boolean_t skip)
    {
    int c;

    do
	{
	c=read_char(arg,errors,rinfo,cbinfo,ops_false);
	if(c < 0)
	    return c;
	arg->unarmoured[arg->num_unarmoured++]=c;
	if(arg->num_unarmoured == sizeof arg->unarmoured)
	    flush(arg,cbinfo);
	}
    while(skip && c == '\r');

    return c;
    }

/**
 * \param headers
 * \param key
 *
 * \return header value if found, otherwise NULL
 */
const char *ops_find_header(ops_headers_t *headers,const char *key)
    {
    unsigned n;

    for(n=0 ; n < headers->nheaders ; ++n)
	if(!strcmp(headers->headers[n].key,key))
	    return headers->headers[n].value;
    return NULL;
    }

/**
 * \param dest
 * \param src
 */
void ops_dup_headers(ops_headers_t *dest,const ops_headers_t *src)
    {
    unsigned n;

    dest->headers=malloc(src->nheaders*sizeof *dest->headers);
    dest->nheaders=src->nheaders;

    for(n=0 ; n < src->nheaders ; ++n)
	{
	dest->headers[n].key=strdup(src->headers[n].key);
	dest->headers[n].value=strdup(src->headers[n].value);
	}
    }

/* Note that this skips CRs so implementations always see just
   straight LFs as line terminators */
static int process_dash_escaped(dearmour_arg_t *arg,ops_error_t **errors,
				ops_reader_info_t *rinfo,
				ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_t content;
    ops_parser_content_t content2;
    ops_signed_cleartext_body_t	*body=&content.content.signed_cleartext_body;
    ops_signed_cleartext_trailer_t *trailer
	=&content2.content.signed_cleartext_trailer;
    const char *hashstr;
    ops_hash_t *hash;
    int total;

    hash=malloc(sizeof *hash);
    hashstr=ops_find_header(&arg->headers,"Hash");
    if(hashstr)
	{
	ops_hash_algorithm_t alg;

	alg=ops_hash_algorithm_from_text(hashstr);
	if(alg == OPS_HASH_UNKNOWN)
	    {
	    free(hash);
	    ERR(cbinfo,"Unknown hash algorithm",OPS_E_R_BAD_FORMAT);
	    }
	ops_hash_any(hash,alg);
	}
    else
	ops_hash_md5(hash);

    hash->init(hash);

    body->length=0;
    total=0;
    for( ; ; )
	{
	int c;
	unsigned count;

	if((c=read_char(arg,errors,rinfo,cbinfo,ops_true)) < 0)
	    return -1;
	if(arg->prev_nl && c == '-')
	    {
	    if((c=read_char(arg,errors,rinfo,cbinfo,ops_false)) < 0)
		return -1;
	    if(c != ' ')
		{
		/* then this had better be a trailer! */
		if(c != '-')
		    ERR(cbinfo,"Bad dash-escaping",OPS_E_R_BAD_FORMAT);
		for(count=2 ; count < 5 ; ++count)
		    {
		    if((c=read_char(arg,errors,rinfo,cbinfo,ops_false)) < 0)
			return -1;
		    if(c != '-')
			ERR(cbinfo,"Bad dash-escaping (2)",OPS_E_R_BAD_FORMAT);
		    }
		arg->state=AT_TRAILER_NAME;
		break;
		}
	    /* otherwise we read the next character */
	    if((c=read_char(arg,errors,rinfo,cbinfo,ops_false)) < 0)
		return -1;
	    }
	if(c == '\n' && body->length)
	    {
	    assert(memchr(body->data+1,'\n',body->length-1) == NULL);
	    if(body->data[0] == '\n')
		hash->add(hash,(unsigned char *)"\r",1);
	    hash->add(hash,body->data,body->length);
	    CB(cbinfo,OPS_PTAG_CT_SIGNED_CLEARTEXT_BODY,&content);
	    body->length=0;
	    }
		
	body->data[body->length++]=c;
	++total;
	if(body->length == sizeof body->data)
	    {
	    CB(cbinfo,OPS_PTAG_CT_SIGNED_CLEARTEXT_BODY,&content);
	    body->length=0;
	    }
	}

    assert(body->data[0] == '\n');
    assert(body->length == 1);
    /* don't send that one character, because its part of the trailer. */

    trailer->hash=hash;
    CB(cbinfo,OPS_PTAG_CT_SIGNED_CLEARTEXT_TRAILER,&content2);

    return total;
    }

static void add_header(dearmour_arg_t *arg,const char *key,const char
		       *value)
    {
    arg->headers.headers=realloc(arg->headers.headers,
				 (arg->headers.nheaders+1)
				 *sizeof *arg->headers.headers);
    arg->headers.headers[arg->headers.nheaders].key=strdup(key);
    arg->headers.headers[arg->headers.nheaders].value=strdup(value);
    ++arg->headers.nheaders;
    }

static int parse_headers(dearmour_arg_t *arg,ops_error_t **errors,
			 ops_reader_info_t *rinfo,ops_parse_cb_info_t *cbinfo)
    {
    char *buf;
    unsigned nbuf;
    unsigned size;
    ops_boolean_t first=ops_true;
    ops_parser_content_t content;

    buf=NULL;
    nbuf=size=0;

    for( ;  ; )
	{
	int c;

	if((c=read_char(arg,errors,rinfo,cbinfo,ops_true)) < 0)
	    return -1;

	if(c == '\n')
	    {
	    char *s;

	    if(nbuf == 0)
		break;

	    assert(nbuf < size);
	    buf[nbuf]='\0';

	    s=strchr(buf,':');
	    if(!s)
		if(!first && !arg->allow_headers_without_gap)
		    // then we have seriously malformed armour
		    ERR(cbinfo,"No colon in armour header",OPS_E_R_BAD_FORMAT);
		else
		    {
		    if(first &&
		       !(arg->allow_headers_without_gap || arg->allow_no_gap))
			ERR(cbinfo,"No colon in armour header (2)",
			    OPS_E_R_BAD_FORMAT);
		    // then we have a nasty armoured block with no
		    // headers, not even a blank line.
		    buf[nbuf]='\n';
		    push_back(arg,(unsigned char *)buf,nbuf+1);
		    break;
		    }
	    else
		{
		*s='\0';
		if(s[1] != ' ')
		    ERR(cbinfo,"No space in armour header",OPS_E_R_BAD_FORMAT);
		add_header(arg,buf,s+2);
		nbuf=0;
		}
	    first=ops_false;
	    }
	else
	    {
	    if(size <= nbuf+1)
		{
		size+=size+80;
		buf=realloc(buf,size);
		}
	    buf[nbuf++]=c;
	    }
	}

    free(buf);

    return 1;
    }

static int read4(dearmour_arg_t *arg,ops_error_t **errors,
		 ops_reader_info_t *rinfo,ops_parse_cb_info_t *cbinfo,
		 int *pc,unsigned *pn,unsigned long *pl)
    {
    int n,c;
    unsigned long l=0;

    for(n=0 ; n < 4 ; ++n)
	{
	c=read_char(arg,errors,rinfo,cbinfo,ops_true);
	if(c < 0)
	    {
	    arg->eof64=ops_true;
	    return -1;
	    }
	if(c == '-')
	    break;
	if(c == '=')
	    break;
	l <<= 6;
	if(c >= 'A' && c <= 'Z')
	    l+=c-'A';
	else if(c >= 'a' && c <= 'z')
	    l+=c-'a'+26;
	else if(c >= '0' && c <= '9')
	    l+=c-'0'+52;
	else if(c == '+')
	    l+=62;
	else if(c == '/')
	    l+=63;
	else
	    {
	    --n;
	    l >>= 6;
	    }
	}

    *pc=c;
    *pn=n;
    *pl=l;

    return 4;
    }

unsigned ops_crc24(unsigned checksum,unsigned char c)
    {
    unsigned i;

    checksum ^= c << 16;
    for(i=0 ; i < 8 ; i++)
	{
	checksum <<= 1;
	if(checksum & 0x1000000)
	    checksum ^= CRC24_POLY;
	}
    return checksum&0xffffffL;
    }

static int decode64(dearmour_arg_t *arg,ops_error_t **errors,
		    ops_reader_info_t *rinfo,ops_parse_cb_info_t *cbinfo)
    {
    unsigned n;
    int n2;
    unsigned long l;
    ops_parser_content_t content;
    int c;
    int ret;

    assert(arg->buffered == 0);

    ret=read4(arg,errors,rinfo,cbinfo,&c,&n,&l);
    if(ret < 0)
	ERR(cbinfo,"Badly formed base64",OPS_E_R_BAD_FORMAT);

    if(n == 3)
	{
	if(c != '=')
	    ERR(cbinfo,"Badly terminated base64 (2)",OPS_E_R_BAD_FORMAT);
	arg->buffered=2;
	arg->eof64=ops_true;
	l >>= 2;
	}
    else if(n == 2)
	{
	if(c != '=')
	    ERR(cbinfo,"Badly terminated base64 (3)",OPS_E_R_BAD_FORMAT);
	arg->buffered=1;
	arg->eof64=ops_true;
	l >>= 4;
	c=read_char(arg,errors,rinfo,cbinfo,ops_false);
	if(c != '=')
	    ERR(cbinfo,"Badly terminated base64",OPS_E_R_BAD_FORMAT);
	}
    else if(n == 0)
	{
	if(!arg->prev_nl || c != '=')
	    ERR(cbinfo,"Badly terminated base64 (4)",OPS_E_R_BAD_FORMAT);
	arg->buffered=0;
	}
    else
	{
	assert(n == 4);
	arg->buffered=3;
	assert(c != '-' && c != '=');
	}

    if(arg->buffered < 3 && arg->buffered > 0)
	{
	// then we saw padding
	assert(c == '=');
	c=read_and_eat_whitespace(arg,errors,rinfo,cbinfo,ops_true);
	if(c != '\n')
	    ERR(cbinfo,"No newline at base64 end",OPS_E_R_BAD_FORMAT);
	c=read_char(arg,errors,rinfo,cbinfo,ops_false);
	if(c != '=')
	    ERR(cbinfo,"No checksum at base64 end",OPS_E_R_BAD_FORMAT);
	}

    if(c == '=')
	{
	// now we are at the checksum
	ret=read4(arg,errors,rinfo,cbinfo,&c,&n,&arg->read_checksum);
	if(ret < 0 || n != 4)
	    ERR(cbinfo,"Error in checksum",OPS_E_R_BAD_FORMAT);
	c=read_char(arg,errors,rinfo,cbinfo,ops_true);
	if(arg->allow_trailing_whitespace)
	    c=eat_whitespace(c,arg,errors,rinfo,cbinfo,ops_true);
	if(c != '\n')
	    ERR(cbinfo,"Badly terminated checksum",OPS_E_R_BAD_FORMAT);
	c=read_char(arg,errors,rinfo,cbinfo,ops_false);
	if(c != '-')
	    ERR(cbinfo,"Bad base64 trailer (2)",OPS_E_R_BAD_FORMAT);
	}

    if(c == '-')
	{
	for(n=0 ; n < 4 ; ++n)
	    if(read_char(arg,errors,rinfo,cbinfo,ops_false) != '-')
		ERR(cbinfo,"Bad base64 trailer",OPS_E_R_BAD_FORMAT);
	arg->eof64=ops_true;
	}
    else
	assert(arg->buffered);

    for(n=0 ; n < arg->buffered ; ++n)
	{
	arg->buffer[n]=l;
	l >>= 8;
	}

    for(n2=arg->buffered-1 ; n2 >= 0 ; --n2)
	arg->checksum=ops_crc24(arg->checksum,arg->buffer[n2]);

    if(arg->eof64 && arg->read_checksum != arg->checksum)
	ERR(cbinfo,"Checksum mismatch",OPS_E_R_BAD_FORMAT);

    return 1;
    }

static void base64(dearmour_arg_t *arg)
    {
    arg->state=BASE64;
    arg->checksum=CRC24_INIT;
    arg->eof64=ops_false;
    arg->buffered=0;
    }

// This reader is rather strange in that it can generate callbacks for
// content - this is because plaintext is not encapsulated in PGP
// packets... it also calls back for the text between the blocks.

static int armoured_data_reader(void *dest_,size_t length,ops_error_t **errors,
				ops_reader_info_t *rinfo,
				ops_parse_cb_info_t *cbinfo)
     {
     dearmour_arg_t *arg=ops_reader_get_arg(rinfo);
     ops_parser_content_t content;
     int ret;
     ops_boolean_t first;
     unsigned char *dest=dest_;
     int saved=length;

     if(arg->eof64 && !arg->buffered)
	 assert(arg->state == OUTSIDE_BLOCK || arg->state == AT_TRAILER_NAME);

     while(length > 0)
	 {
	 unsigned count;
	 unsigned n;
	 char buf[1024];
	 int c;

	 flush(arg,cbinfo);
	 switch(arg->state)
	     {
	 case OUTSIDE_BLOCK:
	     /* This code returns EOF rather than EARLY_EOF because if
		we don't see a header line at all, then it is just an
		EOF (and not a BLOCK_END) */
	     while(!arg->seen_nl)
		 if((c=unarmoured_read_char(arg,errors,rinfo,cbinfo,ops_true)) < 0)
		     return 0;

	     /* flush at this point so we definitely have room for the
		header, and so we can easily erase it from the buffer */
	     flush(arg,cbinfo);
	     /* Find and consume the 5 leading '-' */
	     for(count=0 ; count < 5 ; ++count)
		 {
		 if((c=unarmoured_read_char(arg,errors,rinfo,cbinfo,ops_false)) < 0)
		     return 0;
		 if(c != '-')
		     goto reloop;
		 }

	     /* Now find the block type */
	     for(n=0 ; n < sizeof buf-1 ; )
		 {
		 if((c=unarmoured_read_char(arg,errors,rinfo,cbinfo,ops_false)) < 0)
		     return 0;
		 if(c == '-')
		     goto got_minus;
		 buf[n++]=c;
		 }
	     /* then I guess this wasn't a proper header */
	     break;

	 got_minus:
	     buf[n]='\0';

	     /* Consume trailing '-' */
	     for(count=1 ; count < 5 ; ++count)
		 {
		 if((c=unarmoured_read_char(arg,errors,rinfo,cbinfo,ops_false)) < 0)
		     return 0;
		 if(c != '-')
		     /* wasn't a header after all */
		     goto reloop;
		 }

	     /* Consume final NL */
	     if((c=unarmoured_read_char(arg,errors,rinfo,cbinfo,ops_true)) < 0)
		 return 0;
	     if(arg->allow_trailing_whitespace)
		 if((c=eat_whitespace(c,arg,errors,rinfo,cbinfo,
				      ops_true)) < 0)
		    return 0;
	     if(c != '\n')
		 /* wasn't a header line after all */
		 break;

	     /* Now we've seen the header, scrub it from the buffer */
	     arg->num_unarmoured=0;

	     /* But now we've seen a header line, then errors are
		EARLY_EOF */
	     if((ret=parse_headers(arg,errors,rinfo,cbinfo)) <= 0)
		 return -1;

	     if(!strcmp(buf,"BEGIN PGP SIGNED MESSAGE"))
		 {
		 ops_dup_headers(&content.content.signed_cleartext_header.headers,&arg->headers);
		 CB(cbinfo,OPS_PTAG_CT_SIGNED_CLEARTEXT_HEADER,&content);

		 ret=process_dash_escaped(arg,errors,rinfo,cbinfo);
		 if(ret <= 0)
		     return ret;
		 }
	     else
		 {
		 content.content.armour_header.type=buf;
		 content.content.armour_header.headers=arg->headers;
		 memset(&arg->headers,'\0',sizeof arg->headers);
		 CB(cbinfo,OPS_PTAG_CT_ARMOUR_HEADER,&content);
		 base64(arg);
		 }
	     break;

	 case BASE64:
	     first=ops_true;
	     while(length > 0)
		 {
		 if(!arg->buffered)
		     {
		     if(!arg->eof64)
			 {
			 ret=decode64(arg,errors,rinfo,cbinfo);
			 if(ret <= 0)
			     return ret;
			 }
		     if(!arg->buffered)
			 {
			 assert(arg->eof64);
			 if(first)
			     {
			     arg->state=AT_TRAILER_NAME;
			     goto reloop;
			     }
			 return -1;
			 }
		     }

		 assert(arg->buffered);
		 *dest=arg->buffer[--arg->buffered];
		 ++dest;
		 --length;
		 first=ops_false;
		 }
	     if(arg->eof64 && !arg->buffered)
		 arg->state=AT_TRAILER_NAME;
	     break;

	 case AT_TRAILER_NAME:
	     for(n=0 ; n < sizeof buf-1 ; )
		 {
		 if((c=read_char(arg,errors,rinfo,cbinfo,ops_false)) < 0)
		     return -1;
		 if(c == '-')
		     goto got_minus2;
		 buf[n++]=c;
		 }
	     /* then I guess this wasn't a proper trailer */
	     ERR(cbinfo,"Bad ASCII armour trailer",OPS_E_R_BAD_FORMAT);
	     break;

	 got_minus2:
	     buf[n]='\0';

	     /* Consume trailing '-' */
	     for(count=1 ; count < 5 ; ++count)
		 {
		 if((c=read_char(arg,errors,rinfo,cbinfo,ops_false)) < 0)
		     return -1;
		 if(c != '-')
		     /* wasn't a trailer after all */
		     ERR(cbinfo,"Bad ASCII armour trailer (2)",
			 OPS_E_R_BAD_FORMAT);
		 }

	     /* Consume final NL */
	     if((c=read_char(arg,errors,rinfo,cbinfo,ops_true)) < 0)
		 return -1;
	     if(arg->allow_trailing_whitespace)
		 if((c=eat_whitespace(c,arg,errors,rinfo,cbinfo,
				      ops_true)) < 0)
		    return 0;
	     if(c != '\n')
		 /* wasn't a trailer line after all */
		 ERR(cbinfo,"Bad ASCII armour trailer (3)",OPS_E_R_BAD_FORMAT);

	     if(!strncmp(buf,"BEGIN ",6))
		 {
		 if((ret=parse_headers(arg,errors,rinfo,cbinfo)) <= 0)
		     return ret;
		 content.content.armour_header.type=buf;
		 content.content.armour_header.headers=arg->headers;
		 memset(&arg->headers,'\0',sizeof arg->headers);
		 CB(cbinfo,OPS_PTAG_CT_ARMOUR_HEADER,&content);
		 base64(arg);
		 }
	     else
		 {
		 content.content.armour_trailer.type=buf;
		 CB(cbinfo,OPS_PTAG_CT_ARMOUR_TRAILER,&content);
		arg->state=OUTSIDE_BLOCK;
		}
	    break;
	    }
    reloop:
	continue;
	}

    return saved;
    }

static void armoured_data_destroyer(ops_reader_info_t *rinfo)
    { free(ops_reader_get_arg(rinfo)); }

/**
 * \brief 
 * \param parse_info Usual structure containing information about to how to do the parse
 * \param without_gap Allow headers in armoured data that are not separated from the data by a blank line
 * \param no_gap Allow no blank line at the start of armoured data
 * \param trailing_whitespace Allow armoured data to have trailing whitespace where we strictly would not expect it
 */
void ops_reader_push_dearmour(ops_parse_info_t *parse_info,
			      ops_boolean_t without_gap,
			      ops_boolean_t no_gap,
			      ops_boolean_t trailing_whitespace)
    {
    dearmour_arg_t *arg;

    arg=ops_mallocz(sizeof *arg);
    arg->seen_nl=ops_true;
    arg->allow_headers_without_gap=without_gap;
    arg->allow_no_gap=no_gap;
    arg->allow_trailing_whitespace=trailing_whitespace;

    ops_reader_push(parse_info,armoured_data_reader,armoured_data_destroyer,arg);
    }

/**
 * \param parse_info
 */
void ops_reader_pop_dearmour(ops_parse_info_t *pinfo)
    {
    //    dearmour_arg_t *arg=ops_reader_get_arg(ops_parse_get_rinfo(parse_info));
    //    free(arg);
    ops_reader_pop(pinfo);
    }

// EOF