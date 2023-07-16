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
#include "junction/syscall/entry.h"
#include "junction/syscall/seccomp_bpf.h"
#include "junction/syscall/syscall.h"
#include "junction/syscall/systbl.h"

namespace junction {

/* Source: https://outflux.net/teach-seccomp/step-3/example.c
 */
Status<void> _install_seccomp_filter() {
  struct sock_filter filter[] = {
      /* List allowed syscalls. */
      ALLOW_CALADAN_SYSCALL(ioctl),
      ALLOW_CALADAN_SYSCALL(rt_sigreturn),
      ALLOW_CALADAN_SYSCALL(mmap),
      ALLOW_CALADAN_SYSCALL(madvise),
      ALLOW_CALADAN_SYSCALL(mprotect),
      ALLOW_CALADAN_SYSCALL(exit_group),
      ALLOW_CALADAN_SYSCALL(pwritev2),
      ALLOW_CALADAN_SYSCALL(writev),

      // ALLOW_JUNCTION_SYSCALL(ioctl),
      // ALLOW_JUNCTION_SYSCALL(prctl),
      // ALLOW_JUNCTION_SYSCALL(statfs),
      // ALLOW_JUNCTION_SYSCALL(read),
      // ALLOW_JUNCTION_SYSCALL(chdir),

      ALLOW_JUNCTION_SYSCALL(getdents),
      ALLOW_JUNCTION_SYSCALL(getdents64),
      ALLOW_JUNCTION_SYSCALL(newfstatat),
      ALLOW_JUNCTION_SYSCALL(mmap),
      ALLOW_JUNCTION_SYSCALL(munmap),
      ALLOW_JUNCTION_SYSCALL(mprotect),
      ALLOW_JUNCTION_SYSCALL(madvise),
      ALLOW_JUNCTION_SYSCALL(open),
      ALLOW_JUNCTION_SYSCALL(close),
      ALLOW_JUNCTION_SYSCALL(preadv2),
      ALLOW_JUNCTION_SYSCALL(pread64),
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

static_assert(offsetof(k_ucontext, uc_mcontext.rax) == 0x90);

extern "C" [[noreturn]] void syscall_trap_return(void);
asm(R"(
    .globl syscall_trap_return
    .type syscall_trap_return, @function
    syscall_trap_return:

    // store rax in sigframe
    movq %rax, 0x90(%rsp)
    jmp syscall_rt_sigreturn
)");

extern "C" __sighandler void syscall_trap_handler(int nr, siginfo_t *info,
                                                  void *void_context) {
  k_ucontext *ctx = reinterpret_cast<k_ucontext *>(void_context);
  k_sigframe *sigframe = container_of(ctx, k_sigframe, uc);

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

  if (unlikely(!get_uthread_specific())) {
    log_syscall_msg("Intercepted syscall originating in junction", sysn);
    syscall_exit(-1);
  }

  LOG_ONCE(WARN) << "Warning: intercepting syscalls with seccomp traps";

  // Special case for rt_sigreturn, we actually don't care about the current
  // signal frame, since rt_sigreturn is doing a full restore of a different
  // signal frame.
  if (sysn == SYS_rt_sigreturn) {
    usys_rt_sigreturn(ctx->uc_mcontext.rsp);
    std::unreachable();
  }

  uint64_t rsp = ctx->uc_mcontext.rsp - 128;
  bool alt_syscall_stack = false;

  if (thread_self()->tlsvar ==
      static_cast<uint64_t>(ThreadState::kArmedAltstack)) {
    // use syscall stack
    rsp = reinterpret_cast<uint64_t>(
        &thread_self()->stack->usable[STACK_PTR_SIZE]);
    alt_syscall_stack = true;
  }

  k_sigframe *new_frame = sigframe->CopyToStack(&rsp);
  new_frame->InvalidateAltStack();

  // stash a pointer to the sigframe in case we need to restart the syscall
  if (alt_syscall_stack) mythread().SetSyscallFrame(new_frame);

  // force return to syscall_trap_return
  new_frame->pretcode = reinterpret_cast<char *>(syscall_trap_return);

  sysfn_t target_ip;

  // Special case for clone* syscalls, need to save registers
  if (sysn == SYS_clone || sysn == SYS_clone3) {
    thread_tf &tf = thread_self()->junction_tf;

    tf.r8 = ctx->uc_mcontext.r8;
    tf.r9 = ctx->uc_mcontext.r9;
    tf.r10 = ctx->uc_mcontext.r10;
    tf.r11 = ctx->uc_mcontext.r11;
    tf.r12 = ctx->uc_mcontext.r12;
    tf.r13 = ctx->uc_mcontext.r13;
    tf.r14 = ctx->uc_mcontext.r14;
    tf.r15 = ctx->uc_mcontext.r15;
    tf.rdi = ctx->uc_mcontext.rdi;
    tf.rsi = ctx->uc_mcontext.rsi;
    tf.rbp = ctx->uc_mcontext.rbp;
    tf.rbx = ctx->uc_mcontext.rbx;
    tf.rdx = ctx->uc_mcontext.rdx;
    tf.rcx = ctx->uc_mcontext.rcx;
    tf.rip = ctx->uc_mcontext.rcx;

    if (sysn == SYS_clone)
      target_ip = reinterpret_cast<sysfn_t>(usys_clone);
    else
      target_ip = reinterpret_cast<sysfn_t>(usys_clone3);
  } else if (unlikely(GetCfg().strace_enabled())) {
    target_ip = sys_tbl_strace[sysn];
  } else {
    target_ip = sys_tbl[sysn];
  }

  thread_tf tf;
  tf.rsp = reinterpret_cast<uint64_t>(new_frame);
  tf.rip = reinterpret_cast<uint64_t>(target_ip);
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
