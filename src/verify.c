#include "packet.h"
#include "packet-parse.h"
#include "accumulate.h"
#include <unistd.h>

static ops_packet_reader_ret_t reader(unsigned char *dest,unsigned length,
				      void *arg)
    {
    int n=read(0,dest,length);

    if(n == 0)
	return OPS_PR_EOF;

    if(n != length)
	return OPS_PR_EARLY_EOF;
#if 0
    printf("[read 0x%x: ",length);
    hexdump(dest,length);
    putchar(']');
#endif
    return OPS_PR_OK;
    }

int main(int argc,char **argv)
    {
    ops_parse_options_t opt;
    ops_keyring_t keyring;

    memset(&keyring,'\0',sizeof keyring);
    ops_parse_options_init(&opt);
    //    ops_parse_packet_options(&opt,OPS_PTAG_SS_ALL,OPS_PARSE_RAW);
    //    ops_parse_options(&opt,OPS_PTAG_SS_ALL,OPS_PARSE_PARSED);
    //    opt.cb=callback;
    opt._reader=reader;
    ops_parse_and_accumulate(&keyring,&opt);

    return 0;
    }
