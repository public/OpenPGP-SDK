/** \file
 */

#ifndef OPS_LISTS_H
#define OPS_LISTS_H

typedef struct
    {
    unsigned int size;/* num of array slots allocated */
    unsigned int used; /* num of array slots currently used */
    unsigned long *ulongs;
    } ops_ulong_list_t;

void ops_ulong_list_init(ops_ulong_list_t *list);
void ops_ulong_list_free(ops_ulong_list_t *list);
unsigned int ops_ulong_list_add(ops_ulong_list_t *list, unsigned long *ulong);

#endif /* OPS_LISTS_H */
