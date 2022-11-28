#pragma once

extern "C" {
#include <sys/stat.h>
#include <sys/types.h>
struct clone_args;
}

#include <cstdint>

namespace junction {
extern "C" {

long usys_enosys(...);  // Always returns -ENOSYS

// File
long usys_open(const char *pathname, int flags, mode_t mode);
long usys_openat(int dirfd, const char *pathname, int flags, mode_t mode);
void *usys_mmap(void *addr, size_t length, int prot, int flags, int fd,
                off_t offset);
int usys_munmap(void *addr, size_t length);
ssize_t usys_read(int fd, char *buf, size_t len);
ssize_t usys_write(int fd, const char *buf, size_t len);
ssize_t usys_pread64(int fd, char *buf, size_t len, off_t offset);
ssize_t usys_pwrite64(int fd, const char *buf, size_t len, off_t offset);
off_t usys_lseek(int fd, off_t offset, int whence);
int usys_fsync(int fd);
int usys_dup(int oldfd);
int usys_dup2(int oldfd, int newfd);
long usys_close(int fd);
long usys_newfstatat(int dirfd, const char *pathname, struct stat *statbuf,
                     int flags);
long usys_getdents(unsigned int fd, void *dirp, unsigned int count);
long usys_getdents64(unsigned int fd, void *dirp, unsigned int count);

// Proc
pid_t usys_getpid();
pid_t usys_set_tid_address(int *tidptr);
void usys_exit_group(int status);
void usys_exit(int status);
int usys_arch_prctl(int code, unsigned long addr);

long usys_clone3(clone_args *cl_args, size_t size, int (*func)(void *arg),
                 void *arg);

long usys_futex(uint32_t *uaddr, int futex_op, uint32_t val,
                const struct timespec *timeout, uint32_t *uaddr2,
                uint32_t val3);

// Sched
int usys_sched_yield();

// Time
long usys_nanosleep(const struct timespec *req, struct timespec *rem);

}  // extern "C"
}  // namespace junction
