#ifndef REQUIRED_POSIX_H
#define REQUIRED_POSIX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <io.h>
#include <errno.h>
#include <stdbool.h>
#include <fuse.h>
#include "common.h"

long long win_pwrite(int fd, const void *buf, size_t size, off_t offset);
int win_statvfs(const char *path, struct statvfs *ret);
long long win_pread(int fd, void *buf,	size_t count, uint64_t offset);

int win_close(int fd);
int win_open(const char *filename, int oflag);
int win_read(int const fd, void * const buffer, unsigned const buffer_size);
long win_lseek(int fd, long offset, int origin);
int win_write(int fd, const void *buffer, unsigned int count);
int win_truncate(const char* name, size_t length);
int win_fsync(int fd);
#ifdef __cplusplus
}
#endif

#endif
