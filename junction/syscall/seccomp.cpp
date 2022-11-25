#include "junction/syscall/seccomp.hpp"

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "junction/kernel/ksys.h"
#include "junction/syscall/seccomp_bpf.hpp"
#include "junction/syscall/syscall.hpp"
#include "junction/syscall/systbl.hpp"

namespace junction {

/* Source: https://outflux.net/teach-seccomp/step-3/example.c
 * List of syscall numbers: https://filippo.io/linux-syscall-table/
 */
int _install_seccomp_filter() {
  struct sock_filter filter[] = {
      /* Validate architecture. */
      VALIDATE_ARCHITECTURE,
      /* Grab the system call number. */
      EXAMINE_SYSCALL,
      /* List allowed syscalls. */
      ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
      ALLOW_SYSCALL(sigreturn),
#endif

      ALLOW_SYSCALL(write),
      ALLOW_SYSCALL(writev),
      ALLOW_SYSCALL(fstat),
      ALLOW_SYSCALL(lseek),
      ALLOW_SYSCALL(exit),
      ALLOW_SYSCALL(stat),
      ALLOW_SYSCALL(accept),
      ALLOW_SYSCALL(recvfrom),
      ALLOW_SYSCALL(sendto),
      ALLOW_SYSCALL(mmap),
      ALLOW_SYSCALL(ioctl),
      ALLOW_SYSCALL(mprotect),
      ALLOW_SYSCALL(rt_sigaction),
      ALLOW_SYSCALL(getdents),
      ALLOW_SYSCALL(brk),
      ALLOW_SYSCALL(munmap),
      ALLOW_SYSCALL(futex),
      ALLOW_SYSCALL(getcwd),
      ALLOW_SYSCALL(readlink),
      ALLOW_SYSCALL(readlink),
      ALLOW_SYSCALL(sigaltstack),
      ALLOW_SYSCALL(dup),
      ALLOW_SYSCALL(clone),
      ALLOW_SYSCALL(execve),
      ALLOW_SYSCALL(prlimit64),
      ALLOW_SYSCALL(sysinfo),
      ALLOW_SYSCALL(fcntl),
      ALLOW_SYSCALL(geteuid),
      ALLOW_SYSCALL(getegid),
      ALLOW_SYSCALL(getgid),
      ALLOW_SYSCALL(uname),
      ALLOW_SYSCALL(rt_sigreturn),
      ALLOW_SYSCALL(rename),
      ALLOW_SYSCALL(nanosleep),
      ALLOW_SYSCALL(socket),
      ALLOW_SYSCALL(bind),
      ALLOW_SYSCALL(getsockname),
      ALLOW_SYSCALL(sendto),
      ALLOW_SYSCALL(sendto),
      ALLOW_SYSCALL(recvmsg),
      ALLOW_SYSCALL(connect),
      ALLOW_SYSCALL(listen),
      ALLOW_SYSCALL(epoll_create1),
      ALLOW_SYSCALL(epoll_ctl),
      ALLOW_SYSCALL(epoll_wait),
      ALLOW_SYSCALL(select),
      ALLOW_SYSCALL(madvise),
      ALLOW_SYSCALL(restart_syscall),
      ALLOW_SYSCALL(clock_nanosleep),
      ALLOW_SYSCALL(getrandom),
      ALLOW_SYSCALL(getppid),
      ALLOW_SYSCALL(getuid),
      ALLOW_SYSCALL(gettid),
      ALLOW_SYSCALL(access),
      ALLOW_SYSCALL(getdents64),
      ALLOW_SYSCALL(newfstatat),
      ALLOW_SYSCALL(mbind), /* caladan's slab allocator uses this */

      ALLOW_JUNCTION_SYSCALL(openat),
      ALLOW_JUNCTION_SYSCALL(open),
      ALLOW_JUNCTION_SYSCALL(close),
      ALLOW_JUNCTION_SYSCALL(read),
      ALLOW_JUNCTION_SYSCALL(pread64),
      ALLOW_JUNCTION_SYSCALL(pwrite64),
      ALLOW_JUNCTION_SYSCALL(write),
      ALLOW_JUNCTION_SYSCALL(clock_gettime),
      ALLOW_JUNCTION_SYSCALL(writev),
      ALLOW_JUNCTION_SYSCALL(exit_group),

      TRAP,
  };
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(NO_NEW_PRIVS)");
    if (errno == EINVAL) {
      fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
    }
    return 1;
  }

  int rv = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                   SECCOMP_FILTER_FLAG_TSYNC, &prog);
  if (rv) {
    perror("syscall(SECCOMP_SET_MODE_FILTER)");
    return rv;
  }

  return 0;
}

#if 0
/* Since "sprintf" is technically not signal-safe, reimplement %d here. */
static void write_uint(char* buf, unsigned int val) {
  int width = 0;
  unsigned int tens;

  if (val == 0) {
    strcpy(buf, "0");
    return;
  }
  for (tens = val; tens; tens /= 10) ++width;
  buf[width] = '\0';
  for (tens = val; tens; tens /= 10) buf[--width] = '0' + (tens % 10);
}
#endif  // _DEBUG

static __attribute__((__optimize__("-fno-stack-protector"))) void
__signal_handler(int nr, siginfo_t* info, void* void_context) {
  ucontext_t* ctx = (ucontext_t*)(void_context);

  if (info->si_code != SYS_SECCOMP) {
    return;
  }

  if (!ctx) {
    return;
  }

  // Preserve the old errno
  const int old_errno = errno;

  long sysn = static_cast<long>(ctx->uc_mcontext.gregs[REG_SYSCALL]);
  long arg0 = static_cast<long>(ctx->uc_mcontext.gregs[REG_ARG0]);
  long arg1 = static_cast<long>(ctx->uc_mcontext.gregs[REG_ARG1]);
  long arg2 = static_cast<long>(ctx->uc_mcontext.gregs[REG_ARG2]);
  long arg3 = static_cast<long>(ctx->uc_mcontext.gregs[REG_ARG3]);
  long arg4 = static_cast<long>(ctx->uc_mcontext.gregs[REG_ARG4]);
  long arg5 = static_cast<long>(ctx->uc_mcontext.gregs[REG_ARG5]);

#if 0
  // Logging
  const char* const msg_needed = "TRAP Handling SYSCALL: ";

  char buf[128], *pos;
  memcpy(buf, msg_needed, strlen(msg_needed));
  pos = buf + strlen(msg_needed);
  *pos++ = '(';
  size_t slen = strlen(syscall_names[sysn]);
  // This will likely cause a segfault instead of printing
  BUG_ON(pos - buf + slen + 2 > sizeof(buf));
  memcpy(pos, syscall_names[sysn], slen);
  pos += slen;
  *pos++ = ')';
  *pos++ = '\n';

  ksys_write(STDOUT_FILENO, buf, pos - buf);
#endif  // _DEBUG

  auto res = sys_dispatch(arg0, arg1, arg2, arg3, arg4, arg5, sysn);
  ctx->uc_mcontext.gregs[REG_RESULT] = static_cast<unsigned long>(res);

  // Restore the errno
  errno = old_errno;
}

int _install_signal_handler() {
  struct sigaction act;
  sigset_t mask;
  memset(&act, 0, sizeof(act));
  sigemptyset(&mask);
  sigaddset(&mask, SIGSYS);

  act.sa_sigaction = &__signal_handler;
  act.sa_flags = SA_SIGINFO;
  if (sigaction(SIGSYS, &act, NULL) < 0) {
    perror("sigaction");
    return -1;
  }
  if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
    perror("sigprocmask");
    return -1;
  }
  return 0;
}

int install_seccomp_filter() {
  // Install signal handlers for syscalls
  if (_install_signal_handler()) {
    printf("Failed to install signal handler\n");
    return -1;
  }

  // Install syscall filter.
  return _install_seccomp_filter();
}

}  // namespace junction
