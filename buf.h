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

static inline void buf_deref(struct buf *buf)
{
	memset(buf->data, 0, buf->len);
	//kmem_deref(buf);
}

#define buf_ref(buf) kmem_ref(buf)

#endif /* BUF_H_ */
