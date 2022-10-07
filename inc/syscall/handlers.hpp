#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

// Syscall was handled and does not need to be forwarded to the kernel.
const int STATUS_HANDLED = 0;
// Syscall was NOT handled and needs to be forwarded to the kernel.
const int STATUS_FWD_TO_KERNEL = 1;

EXTERNC void* handle_memset(void* s, int c, size_t n,
  void *(*libc_memset)(void *s, int c, size_t n));

EXTERNC int handle_openat(int dirfd, const char* pathname, int flags,
  long* result);
EXTERNC int handle_open(const char* pathname, int flags, mode_t mode,
  long* result);
EXTERNC int handle_close(int,long* result);
EXTERNC int handle_fstat(int fd, struct stat* buf, long* result);
EXTERNC int handle_lseek(int fd, off_t offset, int whence, long* result);
EXTERNC int handle_read(int fd, void* buf, size_t count, long* result);
EXTERNC int handle_write(int fd, const void* buf, size_t count,
  long* result);
EXTERNC int handle_mmap(void* addr, size_t length, int prot, int flags,
  int fd, off_t offset, long* result);
EXTERNC int handle_munmap(void* addr, size_t length);

EXTERNC int preload_file(const char* path, int flags);

#undef EXTERNC