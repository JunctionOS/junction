#pragma once

extern "C" {
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
struct clone_args;
}

#include <cstdint>

namespace junction {
extern "C" {

// File
long usys_open(const char *pathname, int flags, mode_t mode);
long usys_openat(int dirfd, const char *pathname, int flags, mode_t mode);
ssize_t usys_read(int fd, char *buf, size_t len);
ssize_t usys_write(int fd, const char *buf, size_t len);
ssize_t usys_pread64(int fd, char *buf, size_t len, off_t offset);
ssize_t usys_pwrite64(int fd, const char *buf, size_t len, off_t offset);
ssize_t usys_writev(int fd, const iovec *iov, int iovcnt);
ssize_t usys_pwritev(int fd, const iovec *iov, int iovcnt, off_t offset);
ssize_t usys_pwritev2(int fd, const iovec *iov, int iovcnt, off_t offset,
                      int flags);
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

// Memory
int usys_brk(void *addr);
void *usys_mmap(void *addr, size_t length, int prot, int flags, int fd,
                off_t offset);
int usys_mprotect(void *addr, size_t len, int prot);
int usys_munmap(void *addr, size_t length);

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
long usys_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
                  int flags);
long usys_shutdown(int sockfd, int how);
long usys_listen(int sockfd, int backlog);
long usys_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
long usys_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

// Poll
int usys_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int usys_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p,
               const sigset_t *sigmask, size_t sigsetsize);
int usys_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                struct timeval *tv);
int usys_pselect6(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, const struct timespec *ts);
int usys_epoll_create(int size);
int usys_epoll_create1(int flags);
int usys_epoll_ctl(int epfd, int op, int fd, const epoll_event *event);
int usys_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                    int timeout);
int usys_epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                     int timeout, const sigset_t *sigmask);
int usys_epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
                      const struct timespec *timeout, const sigset_t *sigmask);

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
long usys_clock_gettime(clockid_t clk_id, struct timespec *tp);

// Misc
ssize_t usys_getrandom(char *buf, size_t buflen, unsigned int flags);
int usys_sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);

// Signals
long usys_rt_sigaction(int sig, const struct sigaction *action,
                       struct sigaction *oact, size_t sigsetsize);
long usys_rt_sigprocmask(int how, sigset_t *nset, sigset_t *oset,
                         size_t sigsetsize);
long usys_sigaltstack(const stack_t *ss, stack_t *old_ss);

// Eventfd
long usys_eventfd2(unsigned int initval, int flags);
long usys_eventfd(unsigned int initval);

}  // extern "C"
}  // namespace junction
