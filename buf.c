#include "buf.h"
#include <ctype.h>

static void buf_destructor(void *mem)
{
    struct buf *buf = (struct buf *)mem;
    memset(buf->data, 0, buf->len);
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
    uint len = strlen(str) + 1;
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
    memcpy(result->data + b1->len, b2->data, b2->len);
    return result;
}


void buf_dump(struct buf *buf, char *name)
{
    uint cnt = 0;
    uint row_cnt, col_cnt, row_len;

    printf("\n");
    if (name)
        printf("buf: %s, ", name);
    printf("len: %d\n", buf->len);

    while(cnt < buf->len) {
        printf("%.4x - ", cnt);
        row_len = (cnt + 16) < buf->len ? 16 : (buf->len - cnt);
        for (row_cnt = 0; row_cnt < 16; row_cnt++) {
            if (row_cnt < row_len)
                printf("%.2x ", buf->data[cnt + row_cnt]);
            else
                printf("   ");
            if (row_cnt == 7)
                printf(": ");
        }
        printf("| ");
        for (row_cnt = 0; row_cnt < row_len; row_cnt++) {
            u8 b = buf->data[cnt + row_cnt];
            if (isprint(b))
                printf("%c", b);
            else
                printf(".");
        }
        cnt += row_len;
        printf("\n");
    }
}

struct buf *buf_cpy(void *src, uint len)
{
    struct buf *buf = buf_alloc(len);
    if (!buf)
        return NULL;

    memcpy(buf->data, src, len);
    return buf;
}
