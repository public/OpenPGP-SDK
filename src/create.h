#include "types.h"
#include "packet.h"

enum ops_writer_ret_t
    {
    OPS_W_OK		=0,
    OPS_W_ERROR		=1,
    };

typedef ops_writer_ret_t ops_packet_writer_t(const unsigned char *src,
					     unsigned length,
					     ops_writer_flags_t flags,
					     void *arg);

typedef struct
    {
    ops_packet_writer_t *writer;
    void *arg;
    } ops_create_options_t;

int ops_write_ptag(ops_content_tag_t tag,ops_create_options_t *opt);
int ops_write_length(unsigned length,ops_create_options_t *opt);
int ops_write(const void *src,unsigned length,ops_create_options_t *opt);

int ops_write_struct_user_id(ops_user_id_t *id,ops_create_options_t *opt);
int ops_write_user_id(const char *user_id,ops_create_options_t *opt);
