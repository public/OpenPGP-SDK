#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <sys/stat.h>

#include "CUnit/Basic.h"
#include "openpgpsdk/readerwriter.h"

#include "tests.h"

int main()
    {

    //    mem_literal_data=ops_memory_new();
    setup();

    if (CUE_SUCCESS != CU_initialize_registry())
        {
        fprintf(stderr,"ERROR: initializing registry\n");
        return CU_get_error();
        }
    if (NULL == suite_crypto())
        {
        fprintf(stderr,"ERROR: initialising suite_crypto\n");
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_packet_types())
        {
        fprintf(stderr,"ERROR: initialising suite_packet_types\n");
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_rsa_encrypt()) 
        {
        fprintf(stderr,"ERROR: initialising suite_encrypt\n");
        CU_cleanup_registry();
        return CU_get_error();
        }
    if (NULL == suite_rsa_decrypt()) 
        {
        fprintf(stderr,"ERROR: initialising suite_decrypt\n");
        CU_cleanup_registry();
        return CU_get_error();
        }
    if (NULL == suite_rsa_signature()) 
        {
        fprintf(stderr,"ERROR: initialising suite_signature\n");
        CU_cleanup_registry();
        return CU_get_error();
        }
    if (NULL == suite_rsa_verify()) 
        {
        fprintf(stderr,"ERROR: initialising suite_verify\n");
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_rsa_keys())
        {
        fprintf(stderr,"ERROR: initialising suite_rsa_keys\n");
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_cmdline())
        {
        fprintf(stderr,"ERROR: initialising suite_cmdline\n");
        CU_cleanup_registry();
        return CU_get_error();
        }

    // Run tests
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();

    cleanup();

    return CU_get_error();
    }

// EOF
