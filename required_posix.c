#include "required_posix.h"
#include <windows.h>
#include <io.h>
#include <errno.h>
#include <stdbool.h>
#include <fuse.h>
#include "common.h"
#include "buf.h"

long long win_pwrite(int fd, const void *buf, size_t size, off_t offset)
{
    OVERLAPPED  overlapped = {0};
    HANDLE      handle;
    DWORD       result;

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
        print_e("error in WriteFile %d\n", errno);
        return -1;
    }
    _flushall();
    return result;
}

int win_statvfs(const char *path, struct statvfs *ret)
{
  ULONGLONG free_bytes_available; /* for user - similar to bavail */
  ULONGLONG total_number_of_bytes;
  ULONGLONG total_number_of_free_bytes; /* for everyone - bfree */

  if (!GetDiskFreeSpaceEx (path,
                           (PULARGE_INTEGER) &free_bytes_available,
                           (PULARGE_INTEGER) &total_number_of_bytes,
                           (PULARGE_INTEGER) &total_number_of_free_bytes)) {
    print_e("GetDiskFreeSpaceEx");
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

  /* As with stat, -1 indicates a field is not known. */
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

  return 0;
}

int win_fsync(int fd)
{
	HANDLE file = (HANDLE)_get_osfhandle(fd);
	return FlushFileBuffers(file) ? 0 : -1;
}

long long win_pread(int fd, void *buf,	size_t count, uint64_t offset)
{
    DWORD read_bytes = 0;

    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(OVERLAPPED));

    overlapped.OffsetHigh = (uint32_t)((offset & 0xFFFFFFFF00000000LL) >> 32);
    overlapped.Offset = (uint32_t)(offset & 0xFFFFFFFFLL);

    HANDLE file = (HANDLE)_get_osfhandle(fd);
    SetLastError(0);
    long long total_read_bytes = 0;
    while(total_read_bytes < count) {
		bool RF = ReadFile(file, (char *)buf+total_read_bytes, count-total_read_bytes, &read_bytes, &overlapped);
		total_read_bytes += read_bytes;
		print_d("read %d bytes\n", total_read_bytes);
		if (RF)
			continue;
		// For some reason it errors when it hits end of file so we don't want to check that
		if (GetLastError() == ERROR_HANDLE_EOF)
			break;
		errno = GetLastError();
		print_e("Error reading file : %d\n", GetLastError());
		return -1;
    }
    return total_read_bytes;
}

int win_truncate(const char* name, size_t length)
{
	int fd = win_open(name, O_RDWR);
	if (fd == -1) {
		print_e("error opening file %s\n", name);
		return fd;
	}
	int res =  _chsize(fd, length);
	_close(fd);
	return res;
}

int win_close(int fd)
{
	return _close(fd);
}

int win_open(const char *filename, int oflag)
{
	int fd = _open(filename, oflag, _S_IREAD | _S_IWRITE);
	return fd;
/*
	 HANDLE hFile = CreateFile(
			 filename,
			 GENERIC_READ | GENERIC_WRITE,
			 FILE_SHARE_READ | FILE_SHARE_WRITE,// | FILE_SHARE_DELETE,
	         NULL,                  // default security
	         OPEN_EXISTING,         // existing file only
	         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, // normal file
	         NULL);
	 perror("CreateFile");
	 int fd = _open_osfhandle(hFile, O_RDWR);
	 perror("_open_osfhandle");
	 return fd;*/
}

int win_read(int const fd, void * const buffer, unsigned const buffer_size)
{
	return _read(fd, buffer, buffer_size);
	/*HANDLE file = (HANDLE)_get_osfhandle(fd);
	SetLastError(0);
	bool RF = ReadFile(file, buf, count, &read_bytes, &overlapped);

	 // For some reason it errors when it hits end of file so we don't want to check that
	if ((RF == 0) && GetLastError() != ERROR_HANDLE_EOF) {
		errno = GetLastError();
		print_e("Error reading file : %d\n", GetLastError());
		return -1;
	}

	return read_bytes;*/
}

long win_lseek(int fd, long offset, int origin)
{
	return _lseek(fd, offset, origin);
}

int win_write( int fd, const void *buffer, unsigned int count)
{
	return _write(fd, buffer, count);
}
