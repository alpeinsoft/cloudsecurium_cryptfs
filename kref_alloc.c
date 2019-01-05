#include "types.h"
#include "list.h"
#include "kref.h"
#include "kref_alloc.h"
#include <stdarg.h>


struct kralloc {
    char magic[8];
    struct list list;
    struct le le;
    struct kref kref;
    struct kralloc *linked_mem;
    u8 shift_size;
    uint size;
    void (*destructor)(void *mem);
};


static void k_destructor(struct kref *kref)
{
    struct kralloc *a = (struct kralloc *)container_of(kref, struct kralloc, kref);
    struct kralloc *a_root, *a_tmp;
    struct le *le, *safe_le;

    /* find root memory descriptor */
    a_root = a;
    while(a_root->linked_mem) {
        a_root = a_root->linked_mem;

        if(strcmp(a_root->magic, "kralloc") != 0)
            break;
    }

    /* free all linked memories */
    LIST_FOREACH_SAFE(&a_root->list, le, safe_le) {
        a = list_ledata(le);
        list_unlink(le);
        if (a->destructor)
            a->destructor(a + 1);
        strcpy(a->magic, "\0");
        free((u8 *)a - a->shift_size);
    }

    /* free root memory */
    if (a_root->destructor)
        a_root->destructor(a_root + 1);
    strcpy(a_root->magic, "\0");
    free((u8 *)a_root - a_root->shift_size);
}


/**
 * fls - find last (most-significant) bit set
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 */
static inline int fls(int x)
{
        int r = 32;

        if (!x)
                return 0;
        if (!(x & 0xffff0000u)) {
                x <<= 16;
                r -= 16;
        }
        if (!(x & 0xff000000u)) {
                x <<= 8;
                r -= 8;
        }
        if (!(x & 0xf0000000u)) {
                x <<= 4;
                r -= 4;
        }
        if (!(x & 0xc0000000u)) {
                x <<= 2;
                r -= 2;
        }
        if (!(x & 0x80000000u)) {
                x <<= 1;
                r -= 1;
        }
        return r;
}


/**
 * Allocate aligned memory
 * @param size: needed memory size
 * @param flags: kmalloc flags
 * @param align: align divider (4, 8, 16 ant etc.) or 0 if no align
 * @param destructor: destructor for this memory
 */
void *kref_alloc_aligned(int size, uint align, void (*destructor)(void *mem))
{
    struct kralloc *a;
    void *ptr, *end_ptr, *aligned_ptr;

    u8 shift;

    /* fixed align value if incorrect */
    shift = (fls(align) - 1);
    align = 1 << shift;

    ptr = malloc(sizeof(struct kralloc) + size + align);
    if (!ptr)
        return ptr;

    end_ptr = ptr + sizeof(*a);
    if (align && ((ulong)end_ptr % align))
        aligned_ptr = (void *)((((ulong)end_ptr >> shift) + 1) << shift);
    else
        aligned_ptr = end_ptr;

    a = (struct kralloc *)(aligned_ptr - sizeof(*a));
    a->shift_size = ((void *)a - ptr);
    a->size = size;
    strcpy(a->magic, "kralloc");
    memset(&a->list, 0, sizeof a->list);
    memset(&a->le, 0, sizeof a->le);
    a->destructor = destructor;
    kref_init(&a->kref);
    a->linked_mem = NULL; /* mark as root memory */

    return (void *)(a + 1);
}


/**
 * Increase memory link counter
 * @param mem: pointer to memory allocated
 *         with kref_alloc()
 */
void *kmem_ref(void *mem)
{
    struct kralloc *a = (struct kralloc *)mem - 1;

    if(strcmp(a->magic, "kralloc") != 0)
        return NULL;

    if (a->linked_mem)
        kref_get(&a->linked_mem->kref);
    else
        kref_get(&a->kref);
    return mem;
}


/**
 * Return allocated size
 */
uint kmem_size(void *mem)
{
    struct kralloc *a = (struct kralloc *)mem - 1;
    if(strcmp(a->magic, "kralloc") != 0)
        return 0;

    return a->size;
}


/**
 * Link kmem to another kmem. Set mem_new as child of root memory
 * @param mem_new - pointer to memory allocated with kref_alloc()
 * @param mem_parent - pointer to root memory allocated with kref_alloc()
 * @return 0 if ok
 */
int kmem_link_to_kmem(void *mem_new, void *mem_parent)
{
    struct kralloc *a_new = (struct kralloc *)mem_new - 1;
    struct kralloc *a_parent = (struct kralloc *)mem_parent - 1;
    struct kralloc *a_root;

    if(strcmp(a_new->magic, "kralloc") != 0)
        return -1;

    if(strcmp(a_parent->magic, "kralloc") != 0)
        return -1;


    /* find root memory descriptor */
    a_root = a_parent;
    while(a_root->linked_mem) {
        a_root = a_root->linked_mem;

        if(strcmp(a_root->magic, "kralloc") != 0)
            return -1;
    }

    /* add current memory descriptor to
     * head list of all linked descriptors */
    list_append(&a_root->list, &a_new->le, a_new);
    a_new->linked_mem = a_root; /* mark mem_new as child memory */
    return 0;
}


/**
 * Get reference counter value
 * @param mem - pointer to memory allocated with kref_alloc()
 */
int kmem_get_ref_count(void *mem)
{
    struct kralloc *a = (struct kralloc *)mem - 1;
    uint cnt;

    if(strcmp(a->magic, "kralloc") != 0)
        return 0;

    if (a->linked_mem)
        cnt =  a->linked_mem->kref.refcount;
    else
        cnt = a->kref.refcount;
    return cnt;
}

/**
 * Decrease memory link counter and free memory
 * if link counter reach to zero
 * @param mem: pointer to memory allocated
 *         with kref_alloc() memory pointer
 */
void *_kmem_deref(void **mem)
{
    struct kralloc *a;
    int rc;
    void *m;
    if (!mem)
        return NULL;

    m = *mem;

    if (!m)
        return NULL;

    a = (struct kralloc *)m - 1;

    if(strcmp(a->magic, "kralloc") != 0)
        return NULL;

    if (a->linked_mem)
        rc = kref_put(&a->linked_mem->kref, k_destructor);
    else
        rc = kref_put(&a->kref, k_destructor);

    if (rc) {
        *mem = NULL;
        return NULL;
    }

    return m;
}

/**
 * Make sting by format in allocated memory
 * @param flags - GFP_ flags
 * @param fmt - format
 * @return formatted string or NULL if no enought memory
 */
char *kref_sprintf(const char *fmt, ...)
{
    va_list vargs, vargs_tmp;
    void *p;
    size_t len;

    va_start(vargs, fmt);
    va_copy(vargs_tmp, vargs);
    len = vsnprintf(NULL, 0, fmt, vargs_tmp);
    va_end(vargs_tmp);

    p = kref_alloc(len + 1, NULL);
    if (!p)
        return NULL;

    vsnprintf(p, len + 1, fmt, vargs);
    va_end(vargs);
    return p;
}

char *kref_strdub(const char *src)
{
    char *dst;
    int len = strlen(src);
    if (len <= 0)
        return NULL;
    dst = kref_alloc(len, NULL);
    if (!dst)
        return NULL;
    memcpy(dst, src, len);
    return dst;
}

void *kref_concatenate_mem(void *mem1, void *mem2)
{
    uint len1 = kmem_size(mem1);
    uint len2 = kmem_size(mem2);
    byte *result;

    if (!len1 || !len2)
        return NULL;

    result = kref_alloc(len1 + len2, NULL);
    if (!result)
        return NULL;

    memcpy(result, mem1, len1);
    memcpy(result + len1, mem2, len2);
    return result;
}

