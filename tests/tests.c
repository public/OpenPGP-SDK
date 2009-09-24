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

static void list_suites()
    {
    CU_pTestRegistry registry = CU_get_registry();
    printf("There are %d suites\n", registry->uiNumberOfSuites);
    CU_pSuite suite = registry->pSuite;
    while (suite != NULL)
        {
        printf("  %s\n", suite->pName);
        suite = suite->pNext;
        }
    }

static CU_ErrorCode run_suite(const char *name)
    {
    CU_pTestRegistry registry = CU_get_registry();
    CU_pSuite suite = registry->pSuite;
    while (suite != NULL)
        {
        if (strcmp(name, suite->pName) == 0)
            {
              printf("Running \"%s\"\n", suite->pName);
              // CUnit will return an error if suite != NULL. Doh...
              fprintf(stderr, "But this won't work as CUnit is currently broken...");
              return CU_basic_run_suite(suite);
            }
        suite = suite->pNext;
        }
    fprintf(stderr, "Cannot find suite \"%s\"\n", name);
    return CUE_NOSUITE;
    }

int main(int argc, char **argv)
    {
    if (argc > 1)
        {
          if (strncasecmp(argv[1], "-h", 2) == 0 ||
              strncasecmp(argv[1], "--h", 3) == 0)
              {
              printf("Useage: tests <testsuite name> [<testsuite name> ...]\n");
              printf("        tests -l to list test suites\n");
              return 0;
              }
        }
        
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
        fprintf(stderr,"ERROR: initialising suite_rsa_encrypt\n");
        CU_cleanup_registry();
        return CU_get_error();
        }
    if (NULL == suite_rsa_decrypt()) 
        {
        fprintf(stderr,"ERROR: initialising suite_rsa_decrypt\n");
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_rsa_signature()) 
        {
        fprintf(stderr,"ERROR: initialising suite_rsa_signature\n");
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_rsa_verify()) 
        {
        fprintf(stderr,"ERROR: initialising suite_rsa_verify\n");
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_rsa_keys())
        {
        fprintf(stderr,"ERROR: initialising suite_rsa_keys\n");
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_dsa_signature()) 
        {
        fprintf(stderr,"ERROR: initialising suite_dsa_signature\n");
        CU_cleanup_registry();
        return CU_get_error();
        }

    if (NULL == suite_dsa_verify()) 
        {
        fprintf(stderr,"ERROR: initialising suite_dsa_verify\n");
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

    if (argc > 1)
        {
        if (strncasecmp(argv[1], "-l", 2) == 0 ||
            strncasecmp(argv[1], "--l", 3) == 0)
            {
            list_suites();
            return 0;
            }
        else
            {
              int i;
              CU_ErrorCode error = CUE_SUCCESS;
              for (i = 1; i < argc; i++)
                  {
                    if (error == CUE_SUCCESS)
                        {
                        error = run_suite(argv[i]);
                        printf("Error = %d %s\n", error, CU_get_error_msg());
                        }
                  }
            }
        }
    else
        {
        CU_basic_run_tests();
        }
    cleanup();
    CU_cleanup_registry();

    return CU_get_error();
    }

// EOF
