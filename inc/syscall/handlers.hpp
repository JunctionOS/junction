#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

EXTERNC int preload_file(const char* path, int flags);

EXTERNC int handle_openat(int dirfd, const char* pathname, int flags);
EXTERNC int handle_open(const char* pathname, int flags, mode_t mode);
EXTERNC int handle_close(int fd);
EXTERNC int handle_fstat(int fd, struct stat* buf);
EXTERNC off_t handle_lseek(int fd, off_t offset, int whence);
EXTERNC ssize_t handle_read(int fd, void* buf, size_t count);
EXTERNC ssize_t handle_write(int fd, const void* buf, size_t count);

#undef EXTERNC