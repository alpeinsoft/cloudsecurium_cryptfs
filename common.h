#include <stdarg.h>
#include <execinfo.h>
#include "types.h"
#include "buf.h"
#include "list.h"

#ifndef COMMON_H_
#define COMMON_H_

#define print_e(format, ...) { \
    fprintf(stderr, "%s +%d, %s() Error: ", __FILE__, __LINE__, __FUNCTION__); \
    fprintf(stderr, (format), ##__VA_ARGS__); \
}

#ifdef DEBUG
    #define print_d(format, ...) { \
        fprintf(stdout, "%s +%d, %s(): ", __FILE__, __LINE__, __FUNCTION__); \
        fprintf(stdout, (format), ##__VA_ARGS__); \
    }
#else
    #define print_d(format, ...)
#endif

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


int dir_exist(const char *path);
int file_exist(const char *path);
struct buf *file_get_contents(const char *filename);
int file_put_contents(const char *filename, struct buf *buf);
struct list *str_split(const char *path, char sep);

#endif /* COMMON_H_ */
