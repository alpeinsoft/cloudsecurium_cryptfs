#include <stdarg.h>
#include <execinfo.h>
#include "types.h"
#include "buf.h"
#include "list.h"

#ifndef COMMON_H_
#define COMMON_H_

#define print_e(format, ...) { \
    fprintf(stderr, "%s +%d, %s: ", __FILE__, __LINE__, __FUNCTION__); \
    fprintf(stderr, (format), ##__VA_ARGS__); \
}


static inline void print_backtrace()
{
    void* callstack[128];
    int i, frames = backtrace(callstack, 128);
    char** strs = backtrace_symbols(callstack, frames);
    for (i = 0; i < frames; ++i) {
        printf("%s\n", strs[i]);
    }
    free(strs);
}


int dir_exist(char *path);
int file_exist(char *path);
struct buf *file_get_contents(char *filename);
int file_put_contents(char *filename, struct buf *buf);
struct list *str_split(char *path, char sep);

#endif /* COMMON_H_ */
