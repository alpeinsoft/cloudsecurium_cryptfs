#include "buf.h"

static void buf_destructor(void *mem)
{
    struct buf *buf = (struct buf *)mem;
    kmem_deref(buf->data);
}

struct buf *buf_alloc(uint size)
{
    struct buf *buf = kref_alloc(sizeof *buf, buf_destructor);
    if (!buf)
        return NULL;

    buf->data = kref_alloc(size, NULL);
    if (!buf->data)
        return NULL;

    buf->len = size;
    return buf;
}

struct buf *buf_strdub(char *str)
{
	uint len = strlen(str);
	struct buf *buf = buf_alloc(len);
    if (!buf)
        return NULL;

    memcpy(buf->data, str, len);
    return buf;
}

void *buf_concatenate(struct buf *b1, struct buf *b2)
{
	struct buf *result;

	if (!b1->len || !b2->len)
		return NULL;

	result = buf_alloc(b1->len + b2->len);
	if (!result)
		return NULL;

	memcpy(result->data, b1->data, b1->len);
	memcpy(result + b1->len, b2->data, b2->len);
	return result;
}

