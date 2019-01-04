#include <stdio.h>
#include <sys/stat.h>
#include "common.h"

int dir_exist(char *path)
{
    struct stat s;
    int rc;
    rc = stat(path, &s);
    if (rc)
        return FALSE;
    return (s.st_mode & S_IFDIR) && 1;
}

int file_exist(char *path)
{
    struct stat s;
    int rc;
    rc = stat(path, &s);
    if (rc)
        return FALSE;
    return (s.st_mode & S_IFREG) && 1;
}

struct buf *file_get_contents(char *filename)
{
    int fsize = 0;
    int len;
    FILE *fp;
    struct buf *buf;
    u8 *p;

    fp = fopen(filename, "r");
    if(!fp) {
        print_e("Can't open file %s for read\n", filename);
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    rewind(fp);

    buf = buf_alloc(fsize);
    if (!buf) {
        print_e("Can't alloc for file_get_contents\n");
        goto err;
    }

    len = 0;
    p = buf->data;
    while (fsize) {
        len = fread(p, 1, fsize, fp);
        if (len < 0) {
            print_e("read error from file %s\n", filename);
            goto err;
        }
        p += len;
        fsize -= len;
    }
    
    fclose(fp);
    return buf;

err:
    fclose(fp);
    kmem_deref(buf);
    return NULL;
}

int file_put_contents(char *filename, struct buf *buf)
{
    FILE *fp;
    char *p;
    int rc;
    uint len;
    uint dsize = buf->len;

    fp = fopen(filename, "w");
    if(!fp) {
        print_e("Can't open file %s for write\n", filename);
        return -1;
    }

    p = buf->data;
    while (dsize) {
        len = fwrite(p, 1, dsize, fp);
        if (len < 0) {
            print_e("write error in file %s\n", filename);
            fclose(fp);
            return -1;
        }
        p += len;
        dsize -= len;
    }

    fclose(fp);
    return 0;
}

