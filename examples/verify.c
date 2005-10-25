#include <openpgpsdk/packet.h>
#include <openpgpsdk/packet-parse.h>
#include <openpgpsdk/util.h>
#include <openpgpsdk/accumulate.h>
#include <openpgpsdk/keyring.h>
#include <openpgpsdk/validate.h>
#include <unistd.h>
#include <string.h>

int main(int argc,char **argv)
    {
    ops_parse_options_t opt;
    ops_keyring_t keyring;
    ops_reader_fd_arg_t arg;

    OPS_USED(argc);
    OPS_USED(argv);

    ops_init();

    memset(&keyring,'\0',sizeof keyring);
    ops_parse_options_init(&opt);
    arg.fd=0;
    opt.reader_arg=&arg;
    opt.reader=ops_reader_fd;

    ops_parse_and_accumulate(&keyring,&opt);

    ops_dump_keyring(&keyring);

    ops_validate_all_signatures(&keyring);

    ops_keyring_free(&keyring);

    ops_finish();

    return 0;
    }
