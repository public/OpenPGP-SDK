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

#include "CUnit/Basic.h"

#include <openpgpsdk/types.h>
#include "openpgpsdk/keyring.h"
#include <openpgpsdk/armour.h>
#include "openpgpsdk/memory.h"
#include "openpgpsdk/packet.h"
#include "openpgpsdk/packet-parse.h"
#include "openpgpsdk/util.h"
#include "openpgpsdk/std_print.h"
#include "openpgpsdk/readerwriter.h"
#include "openpgpsdk/validate.h"

#include "../src/lib/parse_local.h"

#include "tests.h"

static int debug=0;

static char *filename_rsa_armour_nopassphrase="gpg_rsa_sign_armour_nopassphrase.txt";
static char *filename_rsa_armour_passphrase="gpg_rsa_sign_armour_passphrase.txt";

static char *filename_rsa_noarmour_nopassphrase="gpg_rsa_sign_noarmour_nopassphrase.txt";
static char *filename_rsa_noarmour_passphrase="gpg_rsa_sign_noarmour_passphrase.txt";
static char *filename_rsa_noarmour_fail_bad_sig="gpg_rsa_sign_noarmour_fail_bad_sig.txt";

static char *filename_rsa_clearsign_nopassphrase="gpg_rsa_clearsign_nopassphrase.txt";
static char *filename_rsa_clearsign_passphrase="gpg_rsa_clearsign_passphrase.txt";
static char *filename_rsa_clearsign_fail_bad_sig="gpg_rsa_clearsign_fail_bad_sig.txt";
static char *filename_rsa_noarmour_compress_base="gpg_rsa_sign_noarmour_compress";
static char *filename_rsa_armour_compress_base="gpg_rsa_sign_armour_compress";

static char *filename_rsa_v3sig="gpg_rsa_sign_v3sig.txt";

static char *filename_rsa_hash_md5="gpg_rsa_hash_md5.txt";

typedef ops_parse_cb_return_t (*ops_callback)(const ops_parser_content_t *, ops_parse_cb_info_t *);

/* Signature verification suite initialization.
 * Create temporary test files.
 */

int init_suite_rsa_verify(void)
    {
    char cmd[MAXBUF+1];

    // Create SIGNED test files

    create_small_testfile(filename_rsa_armour_nopassphrase);
    create_small_testfile(filename_rsa_armour_passphrase);

    create_small_testfile(filename_rsa_v3sig);
    create_small_testfile(filename_rsa_hash_md5);

    create_small_testfile(filename_rsa_noarmour_nopassphrase);
    create_small_testfile(filename_rsa_noarmour_passphrase);
    create_small_testfile(filename_rsa_noarmour_fail_bad_sig);

    // Now sign the test files with GPG

    snprintf(cmd,sizeof cmd,"cat %s/%s | %s --openpgp --compress-level 0 --sign --local-user %s > %s/%s.gpg",
             dir, filename_rsa_noarmour_nopassphrase,
             gpgcmd, alpha_name, dir, filename_rsa_noarmour_nopassphrase);
    if (system(cmd))
        { return 1; }

    snprintf(cmd,sizeof cmd,"cat %s/%s | %s --openpgp --compress-level 0 --sign --local-user %s --armor > %s/%s.asc",
             dir, filename_rsa_armour_nopassphrase,
             gpgcmd, alpha_name, dir, filename_rsa_armour_nopassphrase);
    if (system(cmd))
        { return 1; }

    snprintf(cmd,sizeof cmd,"cat %s/%s | %s --openpgp --compress-level 0 --sign --local-user %s --passphrase %s > %s/%s.gpg",
             dir, filename_rsa_noarmour_passphrase,
             gpgcmd, bravo_name, bravo_passphrase, dir, filename_rsa_noarmour_passphrase);
    if (system(cmd))
        { return 1; }

    snprintf(cmd,sizeof cmd,"cat %s/%s | %s --openpgp --compress-level 0 --sign --local-user %s --passphrase %s --armor > %s/%s.asc",
             dir, filename_rsa_armour_passphrase,
             gpgcmd, bravo_name, bravo_passphrase, dir, filename_rsa_armour_passphrase);
    if (system(cmd))
        { return 1; }

    snprintf(cmd,sizeof cmd,"cat %s/%s | %s --openpgp --compress-level 0 --sign --local-user %s > %s/%s.gpg",
             dir, filename_rsa_noarmour_fail_bad_sig,
             gpgcmd, alpha_name, dir, filename_rsa_noarmour_fail_bad_sig);
    if (system(cmd))
        { return 1; }

    // V3 signature
    snprintf(cmd,sizeof cmd,"cat %s/%s | %s --compress-level 0 --sign --force-v3-sigs --local-user %s > %s/%s.gpg",
             dir, filename_rsa_v3sig,
             gpgcmd, alpha_name, dir, filename_rsa_v3sig);
    if (system(cmd))
        { return 1; }

    // MD5 hash
    snprintf(cmd,sizeof cmd,"cat %s/%s | %s --compress-level 0 --sign --digest-algo \"MD5\" --local-user %s > %s/%s.gpg",
             dir, filename_rsa_hash_md5,
             gpgcmd, alpha_name, dir, filename_rsa_hash_md5);
    if (system(cmd))
        { return 1; }

    /*
     * Create CLEARSIGNED test files
     */

    create_small_testfile(filename_rsa_clearsign_nopassphrase);
    create_small_testfile(filename_rsa_clearsign_passphrase);
    create_small_testfile(filename_rsa_clearsign_fail_bad_sig);

    // and sign them

    snprintf(cmd,sizeof cmd,"cat %s/%s | %s --openpgp --compress-level 0 --clearsign --textmode --local-user %s --armor > %s/%s.asc",
             dir, filename_rsa_clearsign_nopassphrase,
             gpgcmd, alpha_name, dir, filename_rsa_clearsign_nopassphrase);
    if (system(cmd))
        { return 1; }

    snprintf(cmd,sizeof cmd,"cat %s/%s | %s --openpgp --compress-level 0 --clearsign --textmode --local-user %s --passphrase %s --armor > %s/%s.asc",
             dir, filename_rsa_clearsign_passphrase,
             gpgcmd, bravo_name, bravo_passphrase, dir, filename_rsa_clearsign_passphrase);
    if (system(cmd))
        { return 1; }

    snprintf(cmd,sizeof cmd,"cat %s/%s | %s --openpgp --compress-level 0 --clearsign --textmode --local-user %s --armor > %s/%s.asc",
             dir, filename_rsa_clearsign_fail_bad_sig,
             gpgcmd, alpha_name, dir, filename_rsa_clearsign_fail_bad_sig);
    if (system(cmd))
        { return 1; }
    // sig will be turned bad on verification
    // \todo make sig bad here instead

    // compression

    int level=0;
    for (level=0; level<=MAX_COMPRESS_LEVEL; level++)
        {
        char filename[MAXBUF+1];

        // unarmoured
        snprintf(filename, sizeof filename, "%s_%d.txt", 
                 filename_rsa_noarmour_compress_base, level);
        create_small_testfile(filename);

        // just ZIP for now
        snprintf(cmd,sizeof cmd,"cat %s/%s | %s --openpgp --compress-algo \"ZIP\" --compress-level %d --sign --local-user %s > %s/%s.gpg", 
                 dir, filename, 
                 gpgcmd, level, alpha_name, dir, filename);
        if (system(cmd))
            {
            return 1;
            }

        // armoured
        snprintf(filename, sizeof filename, "%s_%d.txt", 
                 filename_rsa_armour_compress_base, level);
        create_small_testfile(filename);

        snprintf(cmd,sizeof cmd,"cat %s/%s | %s --openpgp --compress-algo \"ZIP\" --compress-level %d --sign --armour --local-user %s > %s/%s.asc", 
                 dir, filename, 
                 gpgcmd, level, alpha_name, dir, filename);
        if (system(cmd))
            {
            return 1;
            }
        }
    // Return success
    return 0;
    }

int clean_suite_rsa_verify(void)
    {
    ops_finish();

    reset_vars();

    return 0;
    }

static int test_rsa_verify(const int has_armour, const char *filename, ops_callback callback, ops_parse_info_t *pinfo)
    {
    char signedfile[MAXBUF+1];
    char *suffix= has_armour ? "asc" : "gpg";
    int fd=0;
    validate_data_cb_arg_t validate_arg;
    ops_validate_result_t* result;
    int rtn=0;
    
    result=ops_mallocz(sizeof (ops_validate_result_t));

    // open signed file
    snprintf(signedfile,sizeof signedfile,"%s/%s.%s",
             dir, filename,
             suffix);
#ifdef WIN32
    fd=open(signedfile,O_RDONLY | O_BINARY);
#else
    fd=open(signedfile,O_RDONLY);
#endif
    if(fd < 0)
        {
        perror(signedfile);
        exit(2);
        }
    
    // Set verification reader and handling options

    memset(&validate_arg,'\0',sizeof validate_arg);
    validate_arg.result=result;
    validate_arg.keyring=&pub_keyring;
    validate_arg.rarg=ops_reader_get_arg_from_pinfo(pinfo);

    ops_parse_cb_set(pinfo,callback,&validate_arg);
    ops_reader_set_fd(pinfo,fd);
    pinfo->rinfo.accumulate=ops_true;

    // Set up armour options

    if (has_armour)
        ops_reader_push_dearmour(pinfo,ops_false,ops_false,ops_false);
    
    // Do the verification

    rtn=ops_parse(pinfo);

    if (debug)
        {
        printf("valid=%d, invalid=%d, unknown=%d\n",
               result->valid_count,
               result->invalid_count,
               result->unknown_signer_count);
        }

    // Tidy up
    if (has_armour)
        ops_reader_pop_dearmour(pinfo);

    close(fd);
    ops_validate_result_free(result);

    return (rtn);
    }

static void test_rsa_verify_ok(const int has_armour, const char *filename)
    {
    int rtn=0;
    ops_parse_info_t *pinfo=NULL;

    // setup
    pinfo=ops_parse_info_new();

    // parse
    rtn=test_rsa_verify(has_armour, filename, callback_verify, pinfo);

    // handle result
    ops_print_errors(ops_parse_info_get_errors(pinfo));
    CU_ASSERT(rtn==1);

    // clean up
    ops_parse_info_delete(pinfo);
    }

static void test_rsa_verify_fail(const int has_armour, const char *filename, ops_callback callback, ops_errcode_t expected_errcode)
    {
    int rtn=0;
    ops_parse_info_t *pinfo=NULL;
    ops_callback cb=NULL;
    ops_error_t* errstack=NULL;

    cb = callback==NULL ? callback_verify : callback;

    // setup
    pinfo=ops_parse_info_new();

    // parse
    rtn=test_rsa_verify(has_armour, filename, cb, pinfo);

    // handle result - should fail
    errstack=ops_parse_info_get_errors(pinfo);
    // we are expecting one and only one error
    // print out errors if we have actually got a different error
    CU_ASSERT(errstack!=NULL);

    if (errstack && errstack->errcode!=expected_errcode)
        {
        ops_print_errors(errstack);
        }
    CU_ASSERT(rtn==0);

    // clean up
    ops_parse_info_delete(pinfo);
    }

static void test_rsa_verify_v3sig(void)
    {
    int armour=0;
    assert(pub_keyring.nkeys);

    test_rsa_verify_ok(armour,filename_rsa_v3sig);
    }

static void test_rsa_verify_hash_md5(void)
    {
    int armour=0;
    assert(pub_keyring.nkeys);

    test_rsa_verify_ok(armour,filename_rsa_hash_md5);
    }

static void test_rsa_verify_noarmour_nopassphrase(void)
    {
    int armour=0;
    assert(pub_keyring.nkeys);

    test_rsa_verify_ok(armour,filename_rsa_noarmour_nopassphrase);
    }

static void test_rsa_verify_noarmour_passphrase(void)
    {
    int armour=0;
    assert(pub_keyring.nkeys);
    test_rsa_verify_ok(armour,filename_rsa_noarmour_passphrase);
    }

static void test_rsa_verify_armour_nopassphrase(void)
    {
    int armour=1;
    assert(pub_keyring.nkeys);

    test_rsa_verify_ok(armour,filename_rsa_armour_nopassphrase);
    }

static void test_rsa_verify_armour_passphrase(void)
    {
    int armour=1;
    assert(pub_keyring.nkeys);

    test_rsa_verify_ok(armour,filename_rsa_armour_passphrase);
    }

static void test_rsa_verify_clearsign_nopassphrase(void)
    {
    int armour=1;
    assert(pub_keyring.nkeys);

    test_rsa_verify_ok(armour,filename_rsa_clearsign_nopassphrase);
    }

static void test_rsa_verify_clearsign_passphrase(void)
    {
    int armour=1;
    assert(pub_keyring.nkeys);

    test_rsa_verify_ok(armour,filename_rsa_clearsign_passphrase);
    }

static ops_parse_cb_return_t callback_bad_sig(const ops_parser_content_t* content_, ops_parse_cb_info_t *cbinfo)
    {
    int target;
    unsigned char* data;
    unsigned char orig;
    switch (content_->tag)
        {
    case OPS_PTAG_CT_SIGNED_CLEARTEXT_BODY:
    case OPS_PTAG_CT_LITERAL_DATA_BODY:
        // change something in the signed text to break the sig
        switch (content_->tag)
            {
        case OPS_PTAG_CT_SIGNED_CLEARTEXT_BODY:
            target=content_->content.signed_cleartext_body.length;
            orig=content_->content.signed_cleartext_body.data[target];
            data=(unsigned char*) &content_->content.signed_cleartext_body.data[0];
            break;

        case OPS_PTAG_CT_LITERAL_DATA_BODY:
            target=content_->content.literal_data_body.length;
            orig=content_->content.literal_data_body.data[target];
            data=(unsigned char*) &content_->content.literal_data_body.data[0];
            break;

        default:
            assert(0);
            }

        if (target==0)
            {
            fprintf(stderr,"Nothing in text body to change!!\n");
            break;
            }

        // change a byte somewhere near the middle
        target/=2;
        // remove const-ness so we can change it
        data[target]= ~orig;
        assert(orig!=content_->content.signed_cleartext_body.data[target]);
        break;

    default:
        break;
        }
    return callback_verify(content_,cbinfo);
    }

static void test_rsa_verify_noarmour_fail_bad_sig(void)
    {
    int armour=0;
    assert(pub_keyring.nkeys);

    test_rsa_verify_fail(armour,filename_rsa_noarmour_fail_bad_sig,callback_bad_sig,OPS_E_V_BAD_SIGNATURE);
    }

static void test_rsa_verify_clearsign_fail_bad_sig(void)
    {
    int armour=1;
    assert(pub_keyring.nkeys);

    test_rsa_verify_fail(armour,filename_rsa_clearsign_fail_bad_sig,callback_bad_sig,OPS_E_V_BAD_SIGNATURE);
    }

CU_pSuite suite_rsa_verify()
{
    CU_pSuite suite = NULL;

    suite = CU_add_suite("RSA Verification Suite", init_suite_rsa_verify, clean_suite_rsa_verify);
    if (!suite)
	    return NULL;

    // add tests to suite
    
    if (NULL == CU_add_test(suite, "Clearsigned, no passphrase", test_rsa_verify_clearsign_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Clearsigned, passphrase", test_rsa_verify_clearsign_passphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Armoured, no passphrase", test_rsa_verify_armour_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Armoured, passphrase", test_rsa_verify_armour_passphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Unarmoured, no passphrase", test_rsa_verify_noarmour_nopassphrase))
	    return NULL;
    
    if (NULL == CU_add_test(suite, "Unarmoured, passphrase", test_rsa_verify_noarmour_passphrase))
	    return NULL;

    if (NULL == CU_add_test(suite, "V3 signature verification", test_rsa_verify_v3sig))
	    return NULL;

    if (NULL == CU_add_test(suite, "MD5 Hash", test_rsa_verify_hash_md5))
	    return NULL;

    if (NULL == CU_add_test(suite, "Unarmoured: should fail on bad sig", test_rsa_verify_noarmour_fail_bad_sig))
	    return NULL;
    if (NULL == CU_add_test(suite, "Clearsign: should fail on bad sig", test_rsa_verify_clearsign_fail_bad_sig))
	    return NULL;

    return suite;
}

// EOF
