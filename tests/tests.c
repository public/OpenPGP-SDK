#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "CUnit/Basic.h"
#include "openpgpsdk/readerwriter.h"

#include "tests.h"

extern CU_pSuite suite_packet_types();
extern CU_pSuite suite_crypt_mpi();
extern CU_pSuite suite_rsa_decrypt();
extern CU_pSuite suite_rsa_encrypt();

char dir[MAXBUF+1];

int main()
    {

    if (CUE_SUCCESS != CU_initialize_registry())
	return CU_get_error();

    if (NULL == suite_packet_types())
        {
        CU_cleanup_registry();
        return CU_get_error();
        }

    /*
    if (NULL == suite_rsa_decrypt()) 
        {
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_rsa_encrypt()) 
        {
        CU_cleanup_registry();
        return CU_get_error();
        }
    */

    // Run tests
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
    }

int mktmpdir (void)
    {
    int limit=10; // don't try indefinitely
    long int rnd=0;
    while (limit--) 
	{
	rnd=random();
	snprintf(dir,MAXBUF,"./testdir.%ld",rnd);

	// Try to create directory
	if (!mkdir(dir,0700))
	    {
	    // success
	    return 1;
	    }
	else
	    {
	    fprintf (stderr,"Couldn't open dir: errno=%d\n", errno);
	    perror(NULL);
	    }
	}
    return 0;
    }

void create_testtext(const char *text, char *buf, const int maxlen)
    {
    buf[maxlen]='\0';
    snprintf(buf,maxlen,"%s : Test Text\n", text);
    }

void create_testdata(const char *text, unsigned char *buf, const int maxlen)
    {
    char *preamble=" : Test Data :";
    int i=0;

    snprintf((char *)buf,maxlen,"%s%s", text, preamble);

    for (i=strlen(text)+strlen(preamble); i<maxlen; i++)
        {
        buf[i]=(random() & 0xFF);
        }
    }



