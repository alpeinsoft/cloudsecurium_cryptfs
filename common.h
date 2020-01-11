#include <stdarg.h>
#ifdef __unix__
    #include <execinfo.h>
#endif
#include "types.h"
#include "buf.h"
#include "list.h"

#ifndef COMMON_H_
#define COMMON_H_


#ifdef CRYPTFS_REDIRECT_ERRORS_TO_FILE
    #define print_e(format, ...) do { \
        FILE *f = fopen("/tmp/cs_log_err", "a"); \
        fprintf(f, "%s +%d, %s() Error: ", __FILE__, __LINE__, __FUNCTION__); \
        fprintf(f, (format), ##__VA_ARGS__); \
        fclose(f); \
    } while(0)
#else
    #define print_e(format, ...) do { \
        fprintf(stderr, "%s +%d, %s() Error: ", __FILE__, __LINE__, __FUNCTION__); \
        fprintf(stderr, (format), ##__VA_ARGS__); \
    } while(0)
#endif

#ifdef CRYTPFS_DEBUG
    #ifdef CRYPTFS_REDIRECT_DEBUG_TO_FILE
        #include <unistd.h>
        #define print_d(format, ...) do { \
            FILE *f = fopen("/tmp/cs_log_debug", "a"); \
            fprintf(f, "%s +%d, %s(): ", __FILE__, __LINE__, __FUNCTION__); \
            fprintf(f, (format), ##__VA_ARGS__); \
            fclose(f); \
        } while(0)
    #else
        #define print_d(format, ...) do { \
            fprintf(stdout, "%s +%d, %s(): ", __FILE__, __LINE__, __FUNCTION__); \
            fprintf(stdout, (format), ##__VA_ARGS__); \
            fflush(stdout); \
        } while(0)
    #endif
#else
    #define print_d(format, ...)
#endif

static inline void print_backtrace()
{
#ifdef __unix__
    void* callstack[128];
    int i, frames = backtrace(callstack, 128);
    char** strs = backtrace_symbols(callstack, frames);
    for (i = 0; i < frames; ++i) {
        printf("%s\n", strs[i]);
    }
    free(strs);
#endif
}


int dir_exist(const char *path);
int file_exist(const char *path);
struct buf *file_get_contents(const char *filename);
int file_put_contents(const char *filename, struct buf *buf);
struct list *str_split(const char *path, char sep);

#endif /* COMMON_H_ */
