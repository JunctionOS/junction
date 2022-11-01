#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

EXTERNC unsigned long handle_default(long syscall_number, long arg0 = 0,
                                     long arg1 = 0, long arg2 = 0,
                                     long arg3 = 0, long arg4 = 0,
                                     long arg5 = 0);
EXTERNC unsigned long handle_openat(int dirfd, const char* pathname, int flags);
EXTERNC unsigned long handle_open(const char* pathname, int flags, mode_t mode);
EXTERNC unsigned long handle_close(int fd);
EXTERNC unsigned long handle_fstat(int fd, struct stat* buf);
EXTERNC unsigned long handle_lseek(int fd, off_t offset, int whence);
EXTERNC unsigned long handle_read(int fd, void* buf, size_t count);
EXTERNC unsigned long handle_write(int fd, const void* buf, size_t count);
EXTERNC unsigned long handle_mmap(void* addr, size_t length, int prot,
                                  int flags, int fd, off_t offset);
EXTERNC unsigned long handle_munmap(void* addr, size_t length);

EXTERNC int preload_file(const char* path, int flags);

#undef EXTERNC