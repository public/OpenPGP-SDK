/** \file
 */

#include <assert.h>
#include <fcntl.h>
#ifndef WIN32
#include <unistd.h>
#endif

#include "openpgpsdk/armour.h"
#include "openpgpsdk/crypto.h"
#include "openpgpsdk/packet.h"
#include "openpgpsdk/readerwriter.h"

//static int debug=0;

#define MAXBUF 1024

void ops_encrypt_file(const char* input_filename, const char* output_filename, const ops_keydata_t *pub_key, const int use_armour)
    {
    int fd_in=0;
    int fd_out=0;
    
    ops_create_info_t *cinfo;

    /*
     * Read from test file and write plaintext to memory
     * in set of Literal Data packets
     */


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
    
#ifdef WIN32
    fd_out=open(output_filename,O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
#else
    fd_out=open(output_filename,O_WRONLY | O_CREAT | O_EXCL, 0600);
#endif
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
