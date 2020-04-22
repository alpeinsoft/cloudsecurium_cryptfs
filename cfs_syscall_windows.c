#include "cfs_syscall.h"
#include <windows.h>
#include <stdio.h>
#include <fuse.h>
#include <io.h>
#include <errno.h>
#include <stdbool.h>
#include "types.h"
#include "kref_alloc.h"
#include "common.h"
#include <string.h>

ssize_t cfs_pwrite(int fd, const void *buf, size_t size, off_t offset)
{
    OVERLAPPED overlapped = {0};
    HANDLE handle;
    DWORD result;

    handle = (HANDLE) _get_osfhandle(fd);
    if (handle == INVALID_HANDLE_VALUE)
    {
        errno = EBADF;
        return -1;
    }

    overlapped.Offset = offset;
    if (!WriteFile(handle, buf, size, &result, &overlapped))
    {
        errno = GetLastError();
        return -1;
    }
    return result;
}

int cfs_statvfs(const char *path, struct statvfs *ret)
{
    ULONGLONG free_bytes_available; // for user - similar to bavail
    ULONGLONG total_number_of_bytes;
    ULONGLONG total_number_of_free_bytes; // for everyone - bfree
    char *augmented_path = NULL;

    // GetDiskFreeSpaceExA requires UNC names to be ended with backslash
    if (!strncmp(path, "\\\\?\\", 4) && path[strlen(path)-1] != '\\')
        augmented_path = kref_sprintf("%s\\", path);
    path = augmented_path ? augmented_path : path;

    if (!GetDiskFreeSpaceExA(
            path,
            (PULARGE_INTEGER) &free_bytes_available,
            (PULARGE_INTEGER) &total_number_of_bytes,
            (PULARGE_INTEGER) &total_number_of_free_bytes)) {
        kmem_deref(&augmented_path);
        return -errno;
    }

    if (total_number_of_bytes < 16ULL * 1024 * 1024 * 1024 * 1024)
        ret->f_bsize = 4096;
    else if (total_number_of_bytes < 32ULL * 1024 * 1024 * 1024 * 1024)
        ret->f_bsize = 8192;
    else if (total_number_of_bytes < 64ULL * 1024 * 1024 * 1024 * 1024)
        ret->f_bsize = 16384;
    else if (total_number_of_bytes < 128ULL * 1024 * 1024 * 1024 * 1024)
        ret->f_bsize = 32768;
    else
        ret->f_bsize = 65536;

    // As with stat, -1 indicates a field is not known
    ret->f_frsize = ret->f_bsize;
    ret->f_blocks = total_number_of_bytes / ret->f_bsize;
    ret->f_bfree = total_number_of_free_bytes / ret->f_bsize;
    ret->f_bavail = free_bytes_available / ret->f_bsize;
    ret->f_files = -1;
    ret->f_ffree = -1;
    ret->f_favail = -1;
    ret->f_fsid = -1;
    ret->f_flag = -1;
    ret->f_namemax = FILENAME_MAX;

    kmem_deref(&augmented_path);
    return 0;
}

int cfs_fsync(int fd)
{
    HANDLE file = (HANDLE)_get_osfhandle(fd);
    return FlushFileBuffers(file) ? 0 : -1;
}

ssize_t cfs_pread(int fd, void *buf, size_t count, off_t offset)
{
    DWORD read_bytes = 0;
    OVERLAPPED overlapped;

    memset(&overlapped, 0, sizeof(OVERLAPPED));
    overlapped.OffsetHigh = (uint32_t)((offset & 0xFFFFFFFF00000000LL) >> 32);
    overlapped.Offset = (uint32_t)(offset & 0xFFFFFFFFLL);

    HANDLE file = (HANDLE)_get_osfhandle(fd);
    SetLastError(0);
    ssize_t total_read_bytes = 0;

    while(total_read_bytes < count) {
        bool RF = ReadFile(
                file,
                (u8 *)buf + total_read_bytes,
                count - total_read_bytes,
                &read_bytes,
                &overlapped);
        total_read_bytes += read_bytes;
        if (RF)
            continue;
        // ReadFile errors when it hits end of file so we don't want to check that
        if (GetLastError() == ERROR_HANDLE_EOF)
            break;
        errno = GetLastError();
        return -1;
    }
    return total_read_bytes;
}

int cfs_truncate(const char* name, size_t length)
{
    int fd = cfs_open(name, O_RDWR);
    if (fd == -1)
        return fd;
    int rc =  _chsize(fd, length);
    _close(fd);
    return rc;
}

int cfs_close(int fd)
{
    return _close(fd);
}

int cfs_open(const char *filename, int oflag)
{
    return _open(filename, oflag, _S_IREAD | _S_IWRITE);
}

int cfs_mkdir(const char *path, mode_t mode)
{
    return _mkdir(path);
}

int cfs_rmdir(const char *dirname)
{
    return _rmdir(dirname);
}

int cfs_unlink(const char *filename)
{
    return _unlink(filename);
}

int cfs_access(const char *path, int mode)
{
    return _access(path, mode);
}

int cfs_creat(const char *path, mode_t mode)
{
    return _creat(path, _S_IREAD | _S_IWRITE);
}

int cfs_stat(const char *path, struct _stat * st)
{
    return _stat(path, st);
}

FILE *cfs_fopen(const char *path, const char *mode)
{
    FILE *file = NULL;
    wchar_t *wpath = NULL;
    wchar_t *wmode = NULL;
    int len;

    len = strlen(path) + 1;
    wpath = kref_alloc(2*len, NULL);
    if (!wpath) {
        print_e("Can't allocate memory for path\n");
        goto out;
    }
    if (mbstowcs(wpath, path, len) == -1) {
        print_e("Can't convert path\n");
        goto out;
    }

    len = strlen(mode) + 1;
    wmode = kref_alloc(2*len, NULL);
    if (!wmode) {
        print_e("Can't allocate memory for mode\n");
        goto out;
    }
    if (mbstowcs(wmode, mode, len) == -1) {
        print_e("Can't convert mode\n");
        goto out;
    }

    file = _wfopen(wpath, wmode);
out:
    kmem_deref(&wpath);
    kmem_deref(&wmode);
    return file;
}
