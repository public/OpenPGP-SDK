typedef struct _ops_hash_t ops_hash_t;

typedef void ops_hash_init_t(ops_hash_t *hash);
typedef void ops_hash_add_t(ops_hash_t *hash,const unsigned char *data,
			unsigned length);
typedef unsigned ops_hash_finish_t(ops_hash_t *hash,unsigned char *out);

struct _ops_hash_t
    {
    ops_hash_init_t *init;
    ops_hash_add_t *add;
    ops_hash_finish_t *finish;
    void *data;
    };

void ops_hash_md5(ops_hash_t *hash);
