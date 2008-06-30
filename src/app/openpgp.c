/**
 \file Command line program to perform openpgp operations
*/

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>

#include "openpgpsdk/keyring.h"
#include "openpgpsdk/crypto.h"

//static const char* usage="%s [--homedir name] [--options file] [options] command [args]\n";
static const char* usage="%s --list-keys | --encrypt | --decrypt | --sign | --clearsign | --verify [--keyring=<keyring>] [--userid=<userid>] [--filename=<filename>] [--armour] [--homedir=<homedir>]\n";
static const char* usage_listkeys="%s --list-keys --keyring=<keyring>\n";
static const char* usage_encrypt="%s --encrypt --filename=<filename> --userid=<userid> [--armour] [--homedir=<homedir>]";

static const char* pname;

enum optdefs {
// commands
LISTKEYS=1,
ENCRYPT,
DECRYPT,
SIGN,
CLEARSIGN,
VERIFY,
// options
KEYRING,
USERID,
FILENAME,
ARMOUR,
HOMEDIR
};

static struct option long_options[]=
    {
    // commands
    // --list-keys --keyring
    { "list-keys", no_argument, NULL, LISTKEYS },
    // --encrypt --filename --userid
    { "encrypt", no_argument, NULL, ENCRYPT },
    // --decrypt --filename
    { "decrypt", no_argument, NULL, DECRYPT },
    // --sign --filename
    { "sign", no_argument, NULL, SIGN },
    // --verify --filename
    { "verify", no_argument, NULL, VERIFY },

    // options
    { "keyring", required_argument, NULL, KEYRING },
    { "userid", required_argument, NULL, USERID },
    { "filename", required_argument, NULL, FILENAME },
    { "homedir", required_argument, NULL, HOMEDIR },
    { "armour", no_argument, NULL, ARMOUR },
    { 0,0,0,0},
    };

int main(int argc, char **argv)
    {
    int optindex=0;
    int ch=0;
    int cmd=0;
    int armour=0;

    pname=argv[0];
    const int maxbuf=1024;
    char opt_keyring[maxbuf+1];
    char opt_userid[maxbuf+1];
    char opt_filename[maxbuf+1];
    char opt_homedir[maxbuf+1];
    int got_keyring=0;
    int got_userid=0;
    int got_filename=0;
    char outputfilename[maxbuf+1];
    ops_keyring_t keyring;
    char * default_keyring="~/.gnupg/pubring.gpg";
    char * keyringfile=NULL;
    const ops_keydata_t* keydata;

    memset(opt_keyring,'\0',sizeof(opt_keyring));
    memset(opt_userid,'\0',sizeof(opt_userid));
    memset(opt_filename,'\0',sizeof(opt_filename));
    memset(opt_homedir,'\0',sizeof(opt_homedir));

    memset(outputfilename,'\0',sizeof(outputfilename));

    if (argc<2)
        {
        fprintf(stderr,usage,pname);
        return -1;
        }
    
    // what does the user want to do?

    while((ch=getopt_long(argc,argv,"",long_options,&optindex   )) != -1)
        {
        
        // read options and commands
        
        switch(long_options[optindex].val)
            {
            // commands

        case LISTKEYS:
            cmd=LISTKEYS;
            break;
            
        case ENCRYPT:
            cmd=ENCRYPT;
            break;

        case DECRYPT:
            cmd=DECRYPT;
            break;

        case SIGN:
            cmd=SIGN;
            break;

        case VERIFY:
            cmd=VERIFY;
            break;

            // option

        case KEYRING:
            assert(optarg);
            snprintf(opt_keyring,maxbuf,"%s",optarg);
            got_keyring=1;
            break;
            
        case USERID:
            assert(optarg);
            snprintf(opt_userid,maxbuf,"%s",optarg);
            got_userid=1;
            break;
            
        case FILENAME:
            assert(optarg);
            snprintf(opt_filename,maxbuf,"%s",optarg);
            got_filename=1;
            break;
            
        case ARMOUR:
            armour=1;
            break;
            
        default:
            printf("shouldn't be here\n");
            break;
            }
        }

    // now do the required action
    
    switch(cmd)
        {
    case LISTKEYS:
        if (!got_keyring)
            {
            fprintf(stderr,usage_listkeys,pname);
            return -1;
            }
        
        printf("Listing keys %s\n",opt_keyring);
        ops_keyring_read_from_file(&keyring,armour,opt_keyring);
        ops_keyring_list(&keyring,(char *)NULL);
        ops_keyring_free(&keyring);
        break;
        
    case ENCRYPT:
        if (!got_filename || !got_userid)
            {
            fprintf(stderr,usage_encrypt,pname);
            return -1;
            }
        if (got_keyring)
            keyringfile=opt_keyring;
        else
            keyringfile=default_keyring;
        ops_keyring_read_from_file(&keyring,armour,keyringfile);
        keydata=ops_keyring_find_key_by_userid(&keyring,opt_userid);
        if (!keydata)
            {
            fprintf(stderr,"Userid '%s' not found in keyring '%s'\n",
                    opt_userid, opt_keyring);
            return -1;
            }

        // outputfilename
        char* suffix=armour ? ".ops.asc" : ".ops";
        snprintf(outputfilename,maxbuf,"%s%s", opt_filename,suffix);
        ops_encrypt_file(opt_filename, outputfilename, keydata, armour);

        ops_keyring_free(&keyring);
        break;


    default:
        ;
        }
    
    return 0;
    }
