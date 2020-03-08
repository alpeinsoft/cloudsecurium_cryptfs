#include "cfs_syscall.h"
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

ssize_t cfs_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    return pwrite(fd, buf, count, offset);
}

ssize_t cfs_pread(int fd, void *buf,  size_t count, off_t offset)
{
    return pread(fd, buf, count, offset);
}

int cfs_statvfs(const char *path, struct statvfs *ret)
{
    return statvfs(path, ret);
}

int cfs_close(int fd)
{
    return close(fd);
}

int cfs_open(const char *filename, int oflag)
{
    return open(filename, oflag);
}

int cfs_truncate(const char* name, size_t length)
{
    return truncate(name, length);
}

int cfs_fsync(int fd)
{
    return fsync(fd);
}

int cfs_mkdir(const char *path, mode_t mode)
{
    return mkdir(path, mode);
}

int cfs_rmdir(const char *dirname)
{
    return rmdir(dirname);
}

int cfs_unlink(const char *filename)
{
    return unlink(filename);
}

int cfs_access(const char *path, int mode)
{
    return access(path, mode);
}

int cfs_creat(const char *path, mode_t mode)
{
    return creat(path, mode);
}

int cfs_stat(const char *path, struct stat *st)
{
    return stat(path, st);
}

FILE *cfs_fopen(const char *path, const char *mode)
{
    return fopen(path, mode);
}
