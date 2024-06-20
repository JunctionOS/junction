#include "junction/syscall/seccomp.h"

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

extern "C" {
#include <base/signal.h>
}

#include "junction/bindings/log.h"
#include "junction/junction.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/sigframe.h"
#include "junction/kernel/trapframe.h"
#include "junction/syscall/entry.h"
#include "junction/syscall/seccomp_bpf.h"
#include "junction/syscall/syscall.h"
#include "junction/syscall/systbl.h"

namespace junction {

// Filter for syscalls from the caladan runtime.
static struct sock_filter caladan_filter[] = {
    ALLOW_CALADAN_SYSCALL(ioctl),    ALLOW_CALADAN_SYSCALL(rt_sigreturn),
    ALLOW_CALADAN_SYSCALL(mmap),     ALLOW_CALADAN_SYSCALL(madvise),
    ALLOW_CALADAN_SYSCALL(mprotect), ALLOW_CALADAN_SYSCALL(exit_group),
    ALLOW_CALADAN_SYSCALL(pwritev2), ALLOW_CALADAN_SYSCALL(writev)};

// Syscalls needed to manipulate the host fs.
static struct sock_filter writeable_linux_fs[] = {
    ALLOW_JUNCTION_SYSCALL(mkdirat),   ALLOW_JUNCTION_SYSCALL(linkat),
    ALLOW_JUNCTION_SYSCALL(unlinkat),  ALLOW_JUNCTION_SYSCALL(renameat2),
    ALLOW_JUNCTION_SYSCALL(symlinkat), ALLOW_JUNCTION_SYSCALL(truncate)};

// Syscalls needed to query dents/inodes in the host fs at runtime.
static struct sock_filter uncached_linux_fs[] = {
    ALLOW_JUNCTION_SYSCALL(getdents64), ALLOW_JUNCTION_SYSCALL(newfstatat),
    ALLOW_JUNCTION_SYSCALL(readlinkat)};

// Filter that allows all Junction syscalls to passthrough (for debugging).
static struct sock_filter allow_all_junction[] = {ALLOW_ANY_JUNCTION_SYSCALL};

// Filter to enable tgkill().
static struct sock_filter linux_tgkill[] = {ALLOW_JUNCTION_SYSCALL(tgkill)};

// Final filter that forwards all other system calls to our signal handler.
static struct sock_filter trap[] = {TRAP};

// Filter for core junction functionality.
static struct sock_filter junction_core[] = {
    ALLOW_JUNCTION_SYSCALL(mmap),       ALLOW_JUNCTION_SYSCALL(munmap),
    ALLOW_JUNCTION_SYSCALL(mprotect),   ALLOW_JUNCTION_SYSCALL(madvise),
    ALLOW_JUNCTION_SYSCALL(openat),     ALLOW_JUNCTION_SYSCALL(close),
    ALLOW_JUNCTION_SYSCALL(preadv2),    ALLOW_JUNCTION_SYSCALL(pread64),
    ALLOW_JUNCTION_SYSCALL(exit_group),
};

constexpr size_t filterMax =
    sizeof(caladan_filter) + sizeof(writeable_linux_fs) +
    sizeof(uncached_linux_fs) + sizeof(allow_all_junction) +
    sizeof(linux_tgkill) + sizeof(trap) + sizeof(junction_core);

/* Source: https://outflux.net/teach-seccomp/step-3/example.c
 */
Status<void> _install_seccomp_filter() {
  unsigned char filter[filterMax];
  size_t pos = 0;

  auto addFilter = [&pos, &filter](void *newf, size_t size) {
    if (pos + size > filterMax)
      throw std::runtime_error("seccomp: not enough space in filter");
    memcpy(&filter[pos], newf, size);
    pos += size;
  };

  // Add caladan filters.
  addFilter(caladan_filter, sizeof(caladan_filter));

#ifdef PERMISSIVE_SECCOMP
  // Allow any Junction system call.
  addFilter(allow_all_junction, sizeof(allow_all_junction));
#else

  // Add Junction core filters.
  addFilter(junction_core, sizeof(junction_core));

#ifdef WRITEABLE_LINUX_FS
  // Allow system calls to modify host fs.
  addFilter(writeable_linux_fs, sizeof(writeable_linux_fs));
#endif

  // Add system calls needed to query dirents/inode stats.
  if (!GetCfg().cache_linux_fs())
    addFilter(uncached_linux_fs, sizeof(uncached_linux_fs));

  // Allow tgkill if uintr is not available.
  if (!uintr_enabled) addFilter(linux_tgkill, sizeof(linux_tgkill));

#endif

  // Finally, trap remaining calls.
  addFilter(trap, sizeof(trap));

  struct sock_fprog prog = {
      .len = (unsigned short)(pos / sizeof(struct sock_filter)),
      .filter = (struct sock_filter *)filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(NO_NEW_PRIVS)");
    if (errno == EINVAL) {
      fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
    }
    return MakeError(-errno);
  }

  int rv = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                   SECCOMP_FILTER_FLAG_TSYNC, &prog);
  if (rv) {
    perror("syscall(SECCOMP_SET_MODE_FILTER)");
    return MakeError(rv);
  }

  return {};
}

void log_syscall_msg(const char *msg_needed, long sysn) {
  char buf[128], *pos;
  memcpy(buf, msg_needed, strlen(msg_needed));
  pos = buf + strlen(msg_needed);
  *pos++ = ' ';
  *pos++ = '(';
  size_t slen = strlen(syscall_names[sysn]);
  // This will likely cause a segfault instead of printing
  BUG_ON(pos - buf + slen + 2 > sizeof(buf));
  memcpy(pos, syscall_names[sysn], slen);
  pos += slen;
  *pos++ = ')';
  *pos++ = '\n';
  ksys_write(STDOUT_FILENO, buf, pos - buf);
}

extern "C" void syscall_trap_handler(int nr, siginfo_t *info,
                                     void *void_context) {
  k_ucontext *ctx = reinterpret_cast<k_ucontext *>(void_context);

  if (unlikely(info->si_code != SYS_SECCOMP)) {
    log_syscall_msg("Unexpected signal delivered to syscall handler", 0);
    syscall_exit(-1);
  }

  if (unlikely(!ctx)) {
    log_syscall_msg("Missing context in syscall handler", 0);
    syscall_exit(-1);
  }

  long sysn = static_cast<long>(ctx->uc_mcontext.rax);

  if (unlikely(!preempt_enabled())) {  // call probably from junction libc
    // avoid infinitely looping when Junction's glibc makes a blocked syscall

    static bool once;
    if (!once) {
      once = true;
      log_syscall_msg("Trapped a Junction libc internal syscall ", sysn);
    }

    if (unlikely(
            ctx->uc_mcontext.rip >= reinterpret_cast<uint64_t>(&ksys_start) &&
            ctx->uc_mcontext.rip < reinterpret_cast<uint64_t>(&ksys_end))) {
      ctx->uc_mcontext.rax = -ENOSYS;
      log_syscall_msg("blocked syscall (likely from inside Junction's libc): ",
                      sysn);
      return;
    }

    // We don't allow the brk system call, set the return value to 0 so
    // Junction's libc uses mmap instead.
    if (sysn == __NR_brk) {
      ctx->uc_mcontext.rax = 0;
      return;
    }

    long arg0 = static_cast<long>(ctx->uc_mcontext.rdi);
    long arg1 = static_cast<long>(ctx->uc_mcontext.rsi);
    long arg2 = static_cast<long>(ctx->uc_mcontext.rdx);
    long arg3 = static_cast<long>(ctx->uc_mcontext.r10);
    long arg4 = static_cast<long>(ctx->uc_mcontext.r8);
    long arg5 = static_cast<long>(ctx->uc_mcontext.r9);
    auto res = ksys_default(arg0, arg1, arg2, arg3, arg4, arg5, sysn);
    ctx->uc_mcontext.rax = static_cast<unsigned long>(res);
    return;
  }

  preempt_disable();
  assert_on_runtime_stack();

  if (unlikely(!thread_self())) {
    log_syscall_msg("Unexpected syscall from Caladan", sysn);
    syscall_exit(-1);
  }

  if (unlikely(!IsJunctionThread())) {
    log_syscall_msg("Intercepted syscall originating in junction", sysn);
    syscall_exit(-1);
  }

  if (unlikely(mythread().in_kernel())) {
    log_syscall_msg("Unexpected syscall while in_kernel", sysn);
    syscall_exit(-1);
  }

  LOG_ONCE(WARN) << "Warning: intercepting syscalls with seccomp traps";

  // Special case for rt_sigreturn, we actually don't care about the current
  // signal frame, since rt_sigreturn is doing a full restore of a different
  // signal frame.
  if (sysn == SYS_rt_sigreturn) {
    usys_rt_sigreturn_finish(ctx->uc_mcontext.rsp);
    std::unreachable();
  }

  assert(!IsOnStack(ctx->uc_mcontext.rsp, GetSyscallStack()));

  uint64_t rsp = GetSyscallStackBottom();
  KernelSignalTf &stack_tf = KernelSignalTf(ctx).CloneTo(&rsp);
  k_sigframe &new_frame = stack_tf.GetFrame();

  // stash a copy of rax before the syscall
  new_frame.uc.uc_mcontext.trapno = new_frame.uc.uc_mcontext.rax;
  assert(new_frame.uc.uc_mcontext.trapno >= 0 &&
         new_frame.uc.uc_mcontext.trapno < 4096);

  new_frame.InvalidateAltStack();

  // stash a pointer to the sigframe in case we need to restart the syscall
  mythread().mark_enter_kernel();
  mythread().SetTrapframe(stack_tf);

  // force return to syscall_trap_return
  if (uintr_enabled)
    new_frame.pretcode = reinterpret_cast<char *>(__syscall_trap_return_uintr);
  else
    new_frame.pretcode = reinterpret_cast<char *>(__syscall_trap_return);

  thread_tf tf;

  tf.rip = reinterpret_cast<uint64_t>(sys_tbl[sysn]);
  tf.rsp = reinterpret_cast<uint64_t>(&new_frame);
  tf.rdi = ctx->uc_mcontext.rdi;
  tf.rsi = ctx->uc_mcontext.rsi;
  tf.rdx = ctx->uc_mcontext.rdx;
  tf.r8 = ctx->uc_mcontext.r8;
  tf.r9 = ctx->uc_mcontext.r9;
  tf.rcx = ctx->uc_mcontext.r10;

  // switch stacks and jmp to syscall handler
  __restore_tf_full_and_preempt_enable(&tf);
  std::unreachable();
}

Status<void> _install_signal_handler() {
  struct sigaction act;

  if (sigemptyset(&act.sa_mask) != 0) return MakeError(-errno);

  act.sa_sigaction = &syscall_trap_handler;
  act.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;

  if (base_sigaction(SIGSYS, &act, NULL) < 0) {
    perror("sigaction");
    return MakeError(-errno);
  }

  return {};
}

Status<void> init_seccomp() {
  // Install signal handlers for syscalls
  Status<void> ret = _install_signal_handler();
  if (!ret) return ret;

  // Install syscall filter.
  return _install_seccomp_filter();
}

}  // namespace junction
