#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "CUnit/Basic.h"

extern CU_pSuite suite_rsa_decrypt();
extern CU_pSuite suite_rsa_encrypt();

int main()
    {

    if (CUE_SUCCESS != CU_initialize_registry())
	return CU_get_error();

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
    
    // Run tests
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
    }

