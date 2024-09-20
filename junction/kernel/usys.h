#pragma once

extern "C" {
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
struct clone_args;
}

#include <cstdint>

namespace junction {

extern "C" {

// File
long usys_open(const char *pathname, int flags, mode_t mode);
long usys_openat(int dirfd, const char *pathname, int flags, mode_t mode);
long usys_truncate(const char *path, off_t length);
long usys_ftruncate(int fd, off_t length);
long usys_fallocate(int fd, int mode, off_t offset, off_t len);
long usys_access(const char *pathname, int mode);
long usys_faccessat(int dirfd, const char *pathname, int mode);
long usys_faccessat2(int dirfd, const char *pathname, int mode, int flags);
long usys_chdir(const char *pathname);
long usys_fchdir(int fd);
long usys_mknod(const char *pathname, mode_t mode, dev_t dev);
long usys_mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
long usys_rename(const char *oldpath, const char *newpath);
long usys_renameat(int olddirfd, const char *oldpath, int newdirfd,
                   const char *newpath);
long usys_renameat2(int olddirfd, const char *oldpath, int newdirfd,
                    const char *newpath, unsigned int flags);
long usys_unlinkat(int dirfd, const char *pathname, int flags);
long usys_symlink(const char *target, const char *pathname);
long usys_symlinkat(const char *target, int dirfd, const char *pathname);
ssize_t usys_read(int fd, char *buf, size_t len);
ssize_t usys_readv(int fd, struct iovec *iov, int iovcnt);
ssize_t usys_write(int fd, const char *buf, size_t len);
ssize_t usys_pread64(int fd, char *buf, size_t len, off_t offset);
ssize_t usys_pwrite64(int fd, const char *buf, size_t len, off_t offset);
ssize_t usys_writev(int fd, const iovec *iov, int iovcnt);
ssize_t usys_pwritev(int fd, const iovec *iov, int iovcnt, off_t offset);
ssize_t usys_pwritev2(int fd, const iovec *iov, int iovcnt, off_t offset,
                      int flags);
ssize_t usys_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
off_t usys_lseek(int fd, off_t offset, int whence);
long usys_fsync(int fd);
long usys_fdatasync(int fd);
long usys_dup(int oldfd);
long usys_dup2(int oldfd, int newfd);
long usys_dup3(int oldfd, int newfd, int flags);
long usys_close(int fd);
long usys_close_range(int first, int last, unsigned int flags);
long usys_newfstatat(int dirfd, const char *pathname, struct stat *statbuf,
                     int flags);
long usys_statfs(const char *path, struct statfs *buf);
long usys_fstatfs(int fd, struct statfs *buf);
long usys_stat(const char *path, struct stat *statbuf);
long usys_lstat(const char *path, struct stat *statbuf);
long usys_fstat(int fd, struct stat *statbuf);
long usys_getdents(unsigned int fd, void *dirp, unsigned int count);
long usys_getdents64(unsigned int fd, void *dirp, unsigned int count);
long usys_pipe(int pipefd[2]);
long usys_pipe2(int pipefd[2], int flags);
long usys_fcntl(int fd, unsigned int cmd, unsigned long arg);
long usys_mkdir(const char *pathname, mode_t mode);
long usys_mkdirat(int fd, const char *pathname, mode_t mode);
long usys_rmdir(const char *pathname);
long usys_link(const char *oldpath, const char *newpath);
long usys_linkat(int olddirfd, const char *oldpath, int newdirfd,
                 const char *newpath, int flags);
long usys_unlink(const char *pathname);
long usys_chown(const char *pathname, uid_t owner, gid_t group);
long usys_chmod(const char *pathname, mode_t mode);
long usys_getcwd(char *buf, size_t size);
long usys_umask(mode_t mask);

ssize_t usys_readlink(const char *pathname, char *buf, size_t bufsiz);
ssize_t usys_readlinkat(int dirfd, const char *pathname, char *buf,
                        size_t bufsiz);

// Memory
intptr_t usys_brk(void *addr);
intptr_t usys_mmap(void *addr, size_t len, int prot, int flags, int fd,
                   off_t offset);
long usys_mprotect(void *addr, size_t len, int prot);
long usys_munmap(void *addr, size_t len);
long usys_madvise(void *addr, size_t len, int hint);

// Net
long usys_socket(int domain, int type, int protocol);
long usys_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
long usys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
long usys_getsockopt(int sockfd, int level, int optname, void *optval,
                     socklen_t *optlen);
long usys_setsockopt(int socket, int level, int option_name,
                     const void *option_value, socklen_t option_len);
ssize_t usys_recvfrom(int sockfd, void *buf, size_t len, int flags,
                      struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t usys_sendto(int sockfd, const void *buf, size_t len, int flags,
                    const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t usys_sendmsg(int sockfd, const struct msghdr *msg, int flags);
long usys_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
long usys_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
                  int flags);
long usys_shutdown(int sockfd, int how);
long usys_listen(int sockfd, int backlog);
long usys_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
long usys_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
long usys_socketpair(int domain, int type, int protocol, int sv[2]);

// Poll
long usys_poll(struct pollfd *fds, nfds_t nfds, int timeout);
long usys_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p,
                const sigset_t *sigmask, size_t sigsetsize);
long usys_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                 struct timeval *tv);
long usys_pselect6(int nfds, fd_set *readfds, fd_set *writefds,
                   fd_set *exceptfds, struct timespec *ts,
                   const sigset_t *sigmask);
long usys_epoll_create(int size);
long usys_epoll_create1(int flags);
long usys_epoll_ctl(int epfd, int op, int fd, const epoll_event *event);
long usys_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                     int timeout);
long usys_epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                      int timeout, const sigset_t *sigmask, size_t sigsetsize);
long usys_epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
                       const struct timespec *timeout, const sigset_t *sigmask,
                       size_t sigsetsize);

// Proc
long usys_getpid();
long usys_getppid();
long usys_gettid();
long usys_getpgrp();
long usys_getpgid(pid_t pid);
long usys_setpgid(pid_t pid, pid_t pgid);
long usys_set_tid_address(int *tidptr);
[[noreturn]] void usys_exit_group(int status);
[[noreturn]] void usys_exit(int status);
long usys_arch_prctl(int code, unsigned long addr);
long usys_clone(unsigned long clone_flags, unsigned long newsp,
                uintptr_t parent_tidptr, uintptr_t child_tidptr,
                unsigned long tls);
long usys_clone3(clone_args *cl_args, size_t size);
long usys_vfork();
long usys_futex(uint32_t *uaddr, int futex_op, uint32_t val,
                const struct timespec *timeout, uint32_t *uaddr2,
                uint32_t val3);
long usys_wait4(pid_t pid, int *wstatus, int options, struct rusage *ru);
long usys_waitid(int which, pid_t pid, siginfo_t *infop, int options,
                 struct rusage *ru);
long usys_getsid(pid_t pid);
long usys_setsid();

// Sched
long usys_sched_yield();
long usys_getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *cache);
long usys_sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
long usys_sched_setscheduler(pid_t pid, int policy,
                             const struct sched_param *param);
long usys_sched_getscheduler(pid_t pid);
long usys_sched_setparam(pid_t pid, const struct sched_param *param);
long usys_sched_getparam(pid_t pid, struct sched_param *param);
long usys_sched_get_priority_max(int policy);
long usys_sched_get_priority_min(int policy);

// Time
long usys_nanosleep(const struct timespec *req, struct timespec *rem);
long usys_clock_nanosleep(clockid_t clockid, int flags,
                          const struct timespec *request,
                          struct timespec *remain);

long usys_setitimer(int which, const struct itimerval *new_value,
                    struct itimerval *old_value);
long usys_getitimer(int which, struct itimerval *curr_value);
long usys_alarm(unsigned int seconds);
long usys_gettimeofday(struct timeval *tv, struct timezone *tz);
long usys_settimeofday(const struct timeval *tv, const struct timezone *tz);
long usys_clock_getres(clockid_t clockid, struct timespec *res);
long usys_clock_gettime(clockid_t clockid, struct timespec *tp);
time_t usys_time(time_t *tloc);

// Misc
ssize_t usys_getrandom(char *buf, size_t buflen, unsigned int flags);
long usys_uname(struct utsname *buf);
long usys_getrlimit(int resource, struct rlimit *rlim);
long usys_setrlimit(int resource, const struct rlimit *rlim);
long usys_prlimit64(pid_t pid, int resource, const struct rlimit *new_limit,
                    struct rlimit *old_limit);
long usys_ioctl(int fd, unsigned long request, char *argp);
long usys_sysinfo(struct sysinfo *info);
long usys_getuid();
long usys_geteuid();
long usys_getgid();
long usys_getegid();
long usys_setresuid(uid_t ruid, uid_t euid, uid_t suid);
long usys_setresgid(gid_t rgid, gid_t egid, gid_t sgid);

// Signals
long usys_rt_sigaction(int sig, const struct k_sigaction *action,
                       struct k_sigaction *oact, size_t sigsetsize);
long usys_rt_sigprocmask(int how, const sigset_t *nset, sigset_t *oset,
                         size_t sigsetsize);
long usys_sigaltstack(const stack_t *ss, stack_t *old_ss);
long usys_tgkill(pid_t tgid, pid_t tid, int sig);
long usys_kill(pid_t tgid, int sig);
long usys_rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *info);
long usys_rt_sigpending(sigset_t *sig, size_t sigsetsize);
long usys_rt_sigtimedwait(const sigset_t *set, siginfo_t *info,
                          const struct timespec *ts, size_t sigsetsize);
long usys_rt_sigsuspend(const sigset_t *set, size_t sigsetsize);
long usys_pause();
[[noreturn]] void usys_rt_sigreturn_finish(uint64_t rsp);

// Eventfd
long usys_eventfd2(unsigned int initval, int flags);
long usys_eventfd(unsigned int initval);

// Exec
long usys_execve(const char *filename, const char *argv[], const char *envp[]);
long usys_execveat(int fd, const char *filename, const char *argv[],
                   const char *envp[], int flags);
}

}  // namespace junction
