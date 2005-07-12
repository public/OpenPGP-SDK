/**
 * \file
 *
 * Set of functions to manage a dynamic list
 */

#include "lists.h"

#include <stdlib.h>

/**
 * Initialises ulong list
 * \param *list	Pointer to existing list structure
 */
void ops_ulong_list_init(ops_ulong_list_t *list)
    {
    list->size=0;
    list->used=0;
    list->ulongs=NULL;
    }
 
/**
 * Frees allocated memory in ulong list. Does not free *list itself.
 *
 * \param *list
 */
void ops_ulong_list_free(ops_ulong_list_t *list)
    {
    if (list->ulongs)
	free(list->ulongs);
    ops_ulong_list_init(list);
    }

/**
 * Resizes ulong list.
 *
 * We only resize in one direction - upwards.
 * Algorithm used : double the current size then add 1
 *
 * \param *list	Pointer to list
 * \return 1 if success, else 0
 */

static unsigned int ops_ulong_list_resize(ops_ulong_list_t *list)
    {

    int newsize=0;

    newsize=list->size*2 + 1;
    list->ulongs=realloc(list->ulongs,newsize*sizeof(ulong));
    if (list->ulongs)
	{
	list->size=newsize;
	return 1;
	}
    else
	{
	/* xxx - realloc failed. error message? - rachel */
	return 0;
	}
    }

/**
 * Adds entry to ulong list
 *
 * \param *list
 * \param *ulong
 *
 * \return 1 if success, else 0
 */
unsigned int ops_ulong_list_add(ops_ulong_list_t *list, unsigned long *ulong)
    {
    if (list->size==list->used) 
	if (!ops_ulong_list_resize(list))
	    return 0;

    list->ulongs[list->used]=*ulong;
    list->used++;
    return 1;
    }

