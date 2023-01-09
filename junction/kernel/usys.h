#pragma once

extern "C" {
#include <sys/socket.h>
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
int usys_pipe(int pipefd[2]);
int usys_pipe2(int pipefd[2], int flags);

// Net
long usys_socket(int domain, int type, int protocol);
long usys_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
long usys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
long usys_setsockopt(int socket, int level, int option_name,
                     const void *option_value, socklen_t option_len);
ssize_t usys_recvfrom(int sockfd, void *buf, size_t len, int flags,
                      struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t usys_sendto(int sockfd, const void *buf, size_t len, int flags,
                    const struct sockaddr *dest_addr, socklen_t addrlen);
long usys_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
long usys_shutdown(int sockfd, int how);
long usys_listen(int sockfd, int backlog);

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
long usys_sched_yield();
long usys_getcpu();

// Time
long usys_nanosleep(const struct timespec *req, struct timespec *rem);

// Misc
ssize_t usys_getrandom(char *buf, size_t buflen, unsigned int flags);

}  // extern "C"
}  // namespace junction
