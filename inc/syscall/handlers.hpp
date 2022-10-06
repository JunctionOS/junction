#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

// Indicates that the syscall was handled and does not need to be forwarded to
// the kernel.
const int STATUS_HANDLED = 0;
// Indicates that the syscall was not handled and needs to be forwarded to the
// kernel to be handled.
const int STATUS_FWD_TO_KERNEL = 1;

EXTERNC int preload_file(const char* path, int flags);

EXTERNC int handle_openat(int dirfd, const char* pathname, int flags,
  long* result);
EXTERNC int handle_open(const char* pathname, int flags, mode_t mode,
  long* result);
EXTERNC int handle_close(int,long* result);
EXTERNC int handle_fstat(int fd, struct stat* buf, long* result);
EXTERNC off_t handle_lseek(int fd, off_t offset, int whence, long* result);
EXTERNC ssize_t handle_read(int fd, void* buf, size_t count, long* result);
EXTERNC ssize_t handle_write(int fd, const void* buf, size_t count,
  long* result);

#undef EXTERNC