/** \file
 */

#include <assert.h>
#include <fcntl.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <string.h>

#include "openpgpsdk/armour.h"
#include "openpgpsdk/crypto.h"
#include "openpgpsdk/packet.h"
#include "openpgpsdk/readerwriter.h"
#include "parse_local.h"

//static int debug=0;

#define MAXBUF 1024

static ops_parse_cb_return_t
callback_write_parsed(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo);

void ops_encrypt_file(const char* input_filename, const char* output_filename, const ops_keydata_t *pub_key, const ops_boolean_t use_armour, const ops_boolean_t allow_overwrite)
    {
    int fd_in=0;
    int fd_out=0;
    int flags=0;

    ops_create_info_t *cinfo;

#ifdef WIN32
    fd_in=open(input_filename,O_RDONLY | O_BINARY);
#else
    fd_in=open(input_filename,O_RDONLY);
#endif
    if(fd_in < 0)
        {
        perror(input_filename);
        exit(2);
        }
    
    flags=O_WRONLY | O_CREAT;
    if (allow_overwrite==ops_true)
        flags |= O_TRUNC;
    else
        flags |= O_EXCL;

#ifdef WIN32
    flags |= O_BINARY;
#endif
    fd_out=open(output_filename, flags, 0600);
    if(fd_out < 0)
        {
        perror(output_filename);
        exit(2);
        }
    
    // setup for encrypted writing

    cinfo=ops_create_info_new();
    ops_writer_set_fd(cinfo,fd_out); 

    // set armoured/not armoured here
    if (use_armour)
        ops_writer_push_armoured_message(cinfo);

    // Push the encrypted writer
    ops_writer_push_encrypt_se_ip(cinfo,pub_key);

    // Do the writing

    unsigned char* buf=NULL;
    size_t bufsz=16;
    int done=0;
    for (;;)
        {
        buf=realloc(buf,done+bufsz);
        
	    int n=0;

	    n=read(fd_in,buf+done,bufsz);
	    if (!n)
		    break;
	    assert(n>=0);
        done+=n;
        }

    // This does the writing
    ops_write(buf,done,cinfo);

    // Pop the encrypted writer from the stack
    ops_writer_close(cinfo);

    // tidy up
    close(fd_in);
    close(fd_out);
    ops_create_info_delete(cinfo);
    free(buf);
    }

/* 
the output filename can either be given explicitly, or if NULL,
it will be derived from the input filename following GPG conventions.
That is, we assume a binary encrypted file will be called <origfile>.gpg
and an armoured file will be called <origfile.asc>
If neither is true, then we add a .decrypted suffix.
*/

void ops_decrypt_file(const char* input_filename, const char* output_filename, ops_keyring_t* keyring, const ops_boolean_t use_armour, const ops_boolean_t allow_overwrite, ops_parse_cb_t* cb_get_passphrase)
    {
    int fd_in=0;
    int fd_out=0;
    char* myfilename=NULL;

    //
    ops_parse_info_t *pinfo=NULL;

    // setup for reading from given input file
    fd_in=ops_setup_file_read(&pinfo, input_filename, 
                        NULL,
                        callback_write_parsed,
                        ops_false);

    // setup output filename

    if (output_filename)
        {
        fd_out=ops_setup_file_write(&pinfo->cbinfo.cinfo, output_filename, allow_overwrite);

        // \todo better error handling
        if (fd_out < 0)
            { perror(output_filename); }
        }
    else
        {
        int suffixlen=4;
        char *defaultsuffix=".decrypted";
        const char *suffix=input_filename+strlen((char *)input_filename)-suffixlen;
        if (!strcmp(suffix,".gpg") || !strcmp(suffix,".asc"))
            {
            myfilename=ops_mallocz(strlen(input_filename)-suffixlen+1);
            strncpy(myfilename,input_filename,strlen(input_filename)-suffixlen);
            }
        else
            {
            myfilename=ops_mallocz(strlen(input_filename)+strlen(defaultsuffix)+1);
            sprintf(myfilename,"%s%s",input_filename,defaultsuffix);
            }

        fd_out=ops_setup_file_write(&pinfo->cbinfo.cinfo, myfilename, allow_overwrite);
        
        // \todo better error handling
        if (fd_out < 0)
            { perror(myfilename); }

        free (myfilename);
        }

    if (fd_out < 0)
        {
        // \todo error handling
        exit(2);
        }

    // \todo check for suffix matching armour param

    // setup for writing decrypted contents to given output file

    // setup keyring and passphrase callback
    pinfo->cbinfo.crypt.keyring=keyring;
    pinfo->cbinfo.crypt.cb_get_passphrase=cb_get_passphrase;

    // Set up armour/passphrase options

    if (use_armour)
        ops_reader_push_dearmour(pinfo,ops_false,ops_false,ops_false);
    
    // Do it

    ops_parse_and_print_errors(pinfo);

    // Unsetup

    if (use_armour)
        ops_reader_pop_dearmour(pinfo);

    //    close(fd_in);
//    close(fd_out);
ops_teardown_file_write(pinfo->cbinfo.cinfo, fd_out);
    ops_teardown_file_read(pinfo, fd_in);
// \todo cleardown crypt
//    ops_parse_info_delete(pinfo);
    //    free(buf);
    }

static ops_parse_cb_return_t
callback_write_parsed(const ops_parser_content_t *content_,ops_parse_cb_info_t *cbinfo)
    {
    ops_parser_content_union_t* content=(ops_parser_content_union_t *)&content_->content;
    static ops_boolean_t skipping;
    //    ops_boolean_t write=ops_true;

    OPS_USED(cbinfo);

//    ops_print_packet(content_);

    if(content_->tag != OPS_PTAG_CT_UNARMOURED_TEXT && skipping)
	{
	puts("...end of skip");
	skipping=ops_false;
	}

    switch(content_->tag)
	{
    case OPS_PTAG_CT_UNARMOURED_TEXT:
	printf("OPS_PTAG_CT_UNARMOURED_TEXT\n");
	if(!skipping)
	    {
	    puts("Skipping...");
	    skipping=ops_true;
	    }
	fwrite(content->unarmoured_text.data,1,
	       content->unarmoured_text.length,stdout);
	break;

    case OPS_PTAG_CT_PK_SESSION_KEY:
        return callback_pk_session_key(content_,cbinfo);
        break;

    case OPS_PARSER_CMD_GET_SECRET_KEY:
        return callback_cmd_get_secret_key(content_,cbinfo);
        break;

    case OPS_PARSER_CMD_GET_SK_PASSPHRASE:
        //        return callback_cmd_get_secret_key_passphrase(content_,cbinfo);
        return cbinfo->crypt.cb_get_passphrase(content_,cbinfo);
        break;

    case OPS_PTAG_CT_LITERAL_DATA_BODY:
        return callback_literal_data(content_,cbinfo);
		break;

    case OPS_PTAG_CT_ARMOUR_HEADER:
    case OPS_PTAG_CT_ARMOUR_TRAILER:
    case OPS_PTAG_CT_ENCRYPTED_PK_SESSION_KEY:
    case OPS_PTAG_CT_COMPRESSED:
    case OPS_PTAG_CT_LITERAL_DATA_HEADER:
    case OPS_PTAG_CT_SE_IP_DATA_BODY:
    case OPS_PTAG_CT_SE_IP_DATA_HEADER:
    case OPS_PTAG_CT_SE_DATA_BODY:
    case OPS_PTAG_CT_SE_DATA_HEADER:

	// Ignore these packets 
	// They're handled in ops_parse_one_packet()
	// and nothing else needs to be done
	break;

    default:
        //        return callback_general(content_,cbinfo);
        break;
        //	fprintf(stderr,"Unexpected packet tag=%d (0x%x)\n",content_->tag,
        //		content_->tag);
        //	assert(0);
	}

    return OPS_RELEASE_MEMORY;
    }

// EOF
