#ifndef LIST_H
#define LIST_H

#include <stdio.h>
#include "types.h"

/** Linked-list element */
struct le {
    struct le *prev;    /**< Previous element                    */
    struct le *next;    /**< Next element                        */
    struct list *list;  /**< Parent list (NULL if not linked-in) */
    void *data;         /**< User-data                           */
};

/** List Element Initializer */
#define LE_INIT {NULL, NULL, NULL, NULL}


/** Defines a linked list */
struct list {
    struct le *head;  /**< First list element */
    struct le *tail;  /**< Last list element  */
};

/** Linked list Initializer */
#define LIST_INIT {NULL, NULL}



void list_init(struct list *list);
void list_clear(struct list *list);
void list_append(struct list *list, struct le *le, void *data);
void list_unlink(struct le *le);
struct le *list_head(const struct list *list);
struct le *list_tail(const struct list *list);
int list_count(const struct list *list);


/**
 * Get the user-data from a list element
 *
 * @param le List element
 *
 * @return Pointer to user-data
 */
static inline void *list_ledata(const struct le *le)
{
    return le ? le->data : NULL;
}


static inline bool list_isempty(const struct list *list)
{
    return list ? list->head == NULL : TRUE;
}

static inline struct le *le_next(struct le *le)
{
    return le ? le->next : NULL;
}


#define LIST_FOREACH(list, le) \
    for ((le) = list_head((list)); (le); (le) = (le)->next)

#define LIST_FOREACH_SAFE(list, le, next_le) \
    for ((le) = list_head((list)), (next_le) = le_next(le); (le); (le) = (next_le), (next_le) = le_next(next_le))


#endif // LIST_H
