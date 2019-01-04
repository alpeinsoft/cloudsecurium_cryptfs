#include <stdarg.h>
#include "types.h"
#include "buf.h"
#include "list.h"

#ifndef COMMON_H_
#define COMMON_H_

static inline void print_e(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    fprintf(stderr, "%s +%d: ", __FILE__, __LINE__);
    fprintf(stderr, format, args);
    va_end(args);
}


int dir_exist(char *path);
int file_exist(char *path);
struct buf *file_get_contents(char *filename);
int file_put_contents(char *filename, struct buf *buf);

#endif /* COMMON_H_ */
