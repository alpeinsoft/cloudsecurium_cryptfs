#ifndef BUF_H_
#define BUF_H_

#include "kref_alloc.h"

struct buf {
    u8 *data;
    uint len;
};

struct buf *buf_alloc(uint size);
struct buf *buf_strdub(char *str);

static inline struct buf *bufz_alloc(uint size)
{
    struct buf *buf = buf_alloc(size);
    if (!buf)
        return NULL;
    memset(buf->data, 0, size);
    return buf;
}

#define buf_deref(buf) kmem_deref(buf)
struct buf *buf_cpy(void *src, uint len);
#define buf_ref(buf) kmem_ref(buf);
void *buf_concatenate(struct buf *b1, struct buf *b2);
void buf_dump(struct buf *buf, char *name);

#endif /* BUF_H_ */
