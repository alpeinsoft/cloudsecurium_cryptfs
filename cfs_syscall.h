#ifndef CFS_SYSCALL_H
#define CFS_SYSCALL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"
#ifndef _WIN32
    #include <sys/types.h>
    #include <sys/statvfs.h>
#endif

#ifndef _WIN32
    typedef struct stat CFS_STAT;
    typedef struct stat STAT;
#else
    typedef struct _stat CFS_STAT;
    typedef struct FUSE_STAT STAT;
#endif

ssize_t cfs_pwrite(int fd, const void *buf, size_t count, off_t offset);
ssize_t cfs_pread(int fd, void *buf,  size_t count, off_t offset);
int cfs_statvfs(const char *path, struct statvfs *ret);
int cfs_close(int fd);
int cfs_open(const char *filename, int oflag);
int cfs_truncate(const char* name, size_t length);
int cfs_fsync(int fd);
int cfs_mkdir(const char *path, mode_t mode);
int cfs_rmdir(const char *dirname);
int cfs_unlink(const char *filename);
int cfs_access(const char *path, int mode);
int cfs_creat(const char *path, mode_t mode);
#ifndef _WIN32
    int cfs_stat(const char *path, struct stat *st);
#else
    int cfs_stat(const char *path, struct _stat *st);
#endif
#ifdef __cplusplus
}
#endif

#endif
