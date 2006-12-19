/**
 \file Command line program to perform openpgp operations
*/

#include <stdio.h>
#include <getopt.h>
#include <assert.h>

#include "openpgpsdk/keyring.h"

static const char* usage="%s [--homedir name] [--options file] [options] command [args]\n";
static const char* pname;
static const char* default_public_keyring="/home/rachel/.gnupg/pubring.gpg";
static const char* default_secret_keyring="~/.gnupg/secring.gpg";

enum optdefs {
LISTKEYS=1,
KEYRING,
};

static struct option long_options[]=
    {
    { "list-keys", optional_argument, NULL, LISTKEYS },
    { "keyring", required_argument, NULL, KEYRING },
    { 0,0,0,0},
    };

int main(int argc, char **argv)
    {
    int optindex=0;
    int ch=0;
    int cmd=0;

    pname=argv[0];
    const int maxbuf=1024;
    char keyrings[maxbuf+1]; // keyrings to be used
    char opt_keyrings[maxbuf+1];
    char opt_names[maxbuf+1];
    int opt_use_def_keyrings=1;

    snprintf(keyrings,maxbuf,"%s %s",
	     default_public_keyring,
	     default_secret_keyring);
    opt_keyrings[0]='\0';
    opt_names[0]='\0';

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
	case KEYRING:
	    // option
	    assert(optarg);
	    snprintf(opt_keyrings,maxbuf,"%s",optarg);
	    if (opt_use_def_keyrings)
		snprintf(keyrings,maxbuf,"%s %s %s", 
			 default_public_keyring,
			 default_secret_keyring,
			 opt_keyrings);
	    else
		snprintf(keyrings,maxbuf,"%s",
			 opt_keyrings);
	    break;

	case LISTKEYS:
	    cmd=LISTKEYS;
	    if (optarg)
		snprintf(opt_names,maxbuf,"%s",optarg);
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
	printf("Listing keys %s\n",keyrings);
	// \todo go through all keyrings
	ops_keyring_t keyring;
	ops_keyring_read(&keyring,default_public_keyring);
	ops_keyring_list(&keyring,(char *)NULL);
	ops_keyring_free(&keyring);
	break;

    default:
	;
	}

    return 0;
    }
