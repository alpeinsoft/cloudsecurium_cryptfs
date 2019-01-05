#include <malloc.h>
#include <string.h>
#include "common.h"

#ifndef KREF_ALLOC_H_
#define KREF_ALLOC_H_

void *kref_alloc_aligned(int size, uint align, void (*destructor)(void *mem));
void *kmem_ref(void *mem);
int kmem_link_to_kmem(void *mem_new, void *mem_parent);

void *_kmem_deref(void **mem);
#define kmem_deref(mem) _kmem_deref((void *)(mem))

char *kref_sprintf(const char *fmt, ...);
char *kref_strdub(char *src);
int kmem_get_ref_count(void *mem);
uint kmem_size(void *mem);
void *kref_concatenate_mem(void *mem1, void *mem2);

/**
 * Allocate memory
 * @param size: needed memory size
 * @param flags: kmalloc flags
 * @param destructor: destructor for this memory
 */
static inline void *kref_alloc(uint size, void (*destructor)(void *mem))
{
    void *mem = kref_alloc_aligned(size, 0, destructor);
    if (!mem) {
        print_e("%s +%d: Can't alloc memory\n", __FILE__, __LINE__);
        print_backtrace();
    }
    return mem;
}


/**
 * Allocate zeroed memory
 * @param size: needed memory size
 * @param flags: kmalloc flags
 * @param destructor: destructor for this memory
 */
static inline void *kzref_alloc(uint size, void (*destructor)(void *mem))
{
    void *mem = kref_alloc(size, destructor);
    if (!mem)
        return NULL;

    memset(mem, 0, size);
    return mem;
}


#endif /* KREF_ALLOC_H_ */
