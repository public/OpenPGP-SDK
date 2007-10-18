#ifndef __OPS_STREAMWRITER_H__
#define __OPS_STREAMWRITER_H__

#include <openpgpsdk/readerwriter.h>

void ops_writer_push_stream_encrypt_se_ip(ops_create_info_t *cinfo,
                                          const ops_key_data_t *pub_key);

#endif /*__OPS_STREAMWRITER_H__*/
