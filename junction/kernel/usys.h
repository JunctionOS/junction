#pragma once

extern "C" {
#include <sys/stat.h>
}

namespace junction {

// File
int usys_open(const char *pathname, int flags, mode_t mode);
int usys_openat(int dirfd, const char *pathname, int flags, mode_t mode);
ssize_t usys_read(int fd, char *buf, size_t len);
ssize_t usys_write(int fd, const char *buf, size_t len);
ssize_t usys_pread(int fd, char *buf, size_t len, off_t offset);
ssize_t usys_pwrite64(int fd, const char *buf, size_t len, off_t offset);
off_t usys_lseek(int fd, off_t offset, int whence);
int usys_fsync(int fd);
int usys_dup(int oldfd);
int usys_dup2(int oldfd, int newfd);
int usys_close(int fd);

// Proc
pid_t usys_getpid();

}  // namespace junction
