
extern "C" {
#include <base/signal.h>
#include <base/thread.h>
#include <runtime/preempt.h>
#include <signal.h>
#include <ucontext.h>

#include "lib/caladan/runtime/defs.h"

void jmp_runtime_nosave(runtime_fn_t fn);
void thread_finish_cede(void);
void thread_finish_yield(void);
}

#include <cstring>

#include "junction/bindings/log.h"
#include "junction/junction.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/ucontext.h"
#include "junction/kernel/usys.h"
#include "junction/syscall/strace.h"
#include "junction/syscall/syscall.h"

namespace junction {

inline constexpr size_t kRedzoneSize = 128;
inline constexpr size_t kXsaveAlignment = 64;

inline void print_msg_abort(const char *msg) {
  std::ignore = write(2, msg, strlen(msg));
  syscall_exit(-1);
}

inline bool IsOnStack(uint64_t cur_rsp, const stack_t &ss) {
  uint64_t sp = reinterpret_cast<uint64_t>(ss.ss_sp);

  return cur_rsp >= sp && cur_rsp < sp + ss.ss_size;
}

// The kernel will replace the altstack when we call __rt_sigreturn. Since this
// call may happen from a different kernel thread then the one that the signal
// was delivered to, invalidate the altstack recorded in the sigframe.
inline void InvalidateAltStack(k_sigframe *sigframe) {
  sigframe->uc.uc_stack.ss_flags = 4;
}

// Transfer a kernel-delivered sigframe from to a new stack
k_sigframe *CopySigFrame(uint64_t dest_rsp, const k_sigframe *sigframe) {
  // validate that the kernel used xsave
  BUG_ON(!(sigframe->uc.uc_flags & kUCFpXstate));

  k_xstate *xstate =
      reinterpret_cast<k_xstate *>(sigframe->uc.uc_mcontext.fpstate);
  k_fpx_sw_bytes *fpxs = &xstate->fpstate.sw_reserved;

  // validate magic numbers
  BUG_ON(fpxs->magic1 != kFpXstateMagic1);
  auto *magic2 = reinterpret_cast<unsigned char *>(xstate) + fpxs->xstate_size;
  BUG_ON(*reinterpret_cast<uint32_t *>(magic2) != kFpXstateMagic2);

  // allocate space for xstate
  dest_rsp = AlignDown(dest_rsp - fpxs->extended_size, kXsaveAlignment);
  void *dst_fx_buf = reinterpret_cast<void *>(dest_rsp);
  std::memcpy(dst_fx_buf, xstate, fpxs->extended_size);

  // allocate remainder of sigframe
  dest_rsp -= sizeof(k_sigframe);
  k_sigframe *dst_sigframe = reinterpret_cast<k_sigframe *>(dest_rsp);

  // copy full sigframe
  *dst_sigframe = *sigframe;

  // fix fpstate pointer
  dst_sigframe->uc.uc_mcontext.fpstate =
      reinterpret_cast<_fpstate *>(dst_fx_buf);

  return dst_sigframe;
}

// Transfer sigframe and route signals delivered by IOKernel
extern "C" void DeliverCaladanSignal(void) {
  k_sigframe *sigframe =
      reinterpret_cast<k_sigframe *>(thread_self()->stashed_sigframe);
  uint64_t rsp = sigframe->uc.uc_mcontext.rsp - kRedzoneSize;

  // In a Junction proc thread?
  if (get_uthread_specific()) {
    const stack_t &ss = mythread().get_sighand().get_altstack();
    if (!(ss.ss_flags & SS_DISABLE)) {
      if (!IsOnStack(rsp, ss))
        rsp = reinterpret_cast<uint64_t>(ss.ss_sp) + ss.ss_size;
    }
  }

  // Transfer sigframe to the appropriate stack
  k_sigframe *new_frame =
      CopySigFrame(reinterpret_cast<uint64_t>(rsp), sigframe);
  InvalidateAltStack(new_frame);

  // Ensure the sigframe is immediately restored when this thread next runs
  struct thread_tf &tf = thread_self()->tf;
  tf.rip = reinterpret_cast<uintptr_t>(syscall_rt_sigreturn);
  tf.rsp = reinterpret_cast<uintptr_t>(&new_frame->uc);

  if (sigframe->info.si_signo == SIGUSR1)
    thread_finish_cede();
  else
    thread_finish_yield();
}

// Signal handler for IOKernel sent signals (SIGUSR1 + SIGUSR2)
extern "C" __attribute__((__optimize__("-fno-stack-protector"))) void
caladan_signal_handler(int signo, siginfo_t *info, void *context) {
  STAT(PREEMPTIONS)++;

  /* resume execution if preemption is disabled */
  if (!preempt_enabled()) {
    perthread_andi(preempt_cnt, 0x7fffffff);
    return;
  }

  // cache a pointer to the sigframe in the struct thread
  k_ucontext *uc = reinterpret_cast<k_ucontext *>(context);
  k_sigframe *sigframe = container_of(uc, k_sigframe, uc);
  thread_self()->stashed_sigframe = sigframe;

  if (signo == SIGUSR1) {
    WARN_ON_ONCE(!preempt_cede_needed(myk()));
    preempt_disable();
    jmp_runtime_nosave(DeliverCaladanSignal);
    __builtin_unreachable();
  }

  assert(signo == SIGUSR2);
  /* check if yield request is still relevant */
  if (preempt_yield_needed(myk())) {
    jmp_runtime_nosave(DeliverCaladanSignal);
    __builtin_unreachable();
  }
}

// Trampoline to kernel's rt_sigreturn, places the sigframe at rsp where kernel
// expects it
extern "C" [[noreturn]] void jmp_rt_sigreturn(uint64_t rsp);
asm(R"(
    .globl jmp_rt_sigreturn
    .type jmp_rt_sigreturn, @function
    jmp_rt_sigreturn:

    movq %rdi, %rsp
    jmp syscall_rt_sigreturn
)");

// Unwind a sigframe from a Junction process's thread
extern "C" long usys_rt_sigreturn(uint64_t rsp) {
  k_sigframe *sigframe = reinterpret_cast<k_sigframe *>(rsp - 8);
  ThreadSignalHandler &hand = mythread().get_sighand();

  if (unlikely(GetCfg().strace_enabled())) LogSyscall("rt_sigreturn");

  // set blocked
  hand.UpdateBlocked(sigframe->uc.mask);

  // update altstack
  hand.SigAltStack(&sigframe->uc.uc_stack, nullptr);

  // Clear sigaltstack and signal mask before using kernel to restore
  InvalidateAltStack(sigframe);
  sigframe->uc.mask = 0;

  jmp_rt_sigreturn(rsp);
}

// Sigframes delivered to Junction procs need some fields replaced
void TransformSigFrame(k_sigframe &sigframe, const k_sigaction &act,
                       const ThreadSignalHandler &hand) {
  // fix restorer
  sigframe.pretcode = reinterpret_cast<char *>(act.restorer);

  // fix blocked signal mask
  sigframe.uc.mask = hand.get_blocked_mask();

  // fix altstack
  sigframe.uc.uc_stack = hand.get_altstack();
}

extern "C" [[noreturn]] void jmp_sighandler(int signo, siginfo_t *info,
                                            k_ucontext *uc, uint64_t rsp,
                                            uint64_t rip);
asm(R"(
    .globl jmp_sighandler
    .type jmp_sighandler, @function
    jmp_sighandler:

    movq %rcx, %rsp
    jmpq    *%r8
)");

bool DeliverUserSignal(int signo, siginfo_t *info, k_sigframe *sigframe) {
  ThreadSignalHandler &hand = mythread().get_sighand();
  k_sigaction act = myproc().get_signal_table().get_action(signo);

  if (hand.check_signal_ignored(signo, act)) return false;

  // TODO: better crash?
  if (hand.check_signal_crash(signo, act)) panic("program got fatal signal");

  if (hand.is_sig_blocked(signo)) {
    hand.EnqueueSignal(signo, info);
    return false;
  }

  // signal delivered via non-kernel-sigaction
  if (sigframe == nullptr) return true;

  // Determine stack to use
  uint64_t rsp = sigframe->uc.uc_mcontext.rsp - kRedzoneSize;
  bool switched_to_altstack = false;
  const stack_t &ss = hand.get_altstack();
  if (act.wants_altstack() && hand.has_altstack() && !IsOnStack(rsp, ss)) {
    switched_to_altstack = true;
    rsp = reinterpret_cast<uint64_t>(ss.ss_sp) + ss.ss_size;
  }

  // transfer the frame
  k_sigframe *new_frame = CopySigFrame(rsp, sigframe);

  // fixup the frame
  TransformSigFrame(*new_frame, act, hand);

  // disarm sigstack if needed
  if (switched_to_altstack && ss.ss_flags & kSigStackAutoDisarm)
    hand.DisableAltStack();

  // mask signals
  if (!act.is_nodefer()) hand.set_sig_blocked(signo);

  jmp_sighandler(signo, &new_frame->info, &new_frame->uc,
                 reinterpret_cast<uint64_t>(new_frame),
                 reinterpret_cast<uint64_t>(act.handler));
  __builtin_unreachable();
}

// Signal handler for synchronous fault signals generated by user code. We
// don't expect there to be recursive signals.
extern "C" __attribute__((__optimize__("-fno-stack-protector"))) void
synchronous_signal_handler(int signo, siginfo_t *info, void *context) {
  k_ucontext *uc = reinterpret_cast<k_ucontext *>(context);
  k_sigframe *sigframe = container_of(uc, k_sigframe, uc);

  if (unlikely(!thread_self()))
    print_msg_abort("Unexpected signal delivered to Caladan code");

  if (unlikely(!get_uthread_specific()))
    print_msg_abort("Unexpected signal delivered to Junction code");

  if (unlikely(!preempt_enabled()))
    print_msg_abort("signal delivered while preemption is disabled");

  if (unlikely(mythread().in_syscall()))
    print_msg_abort("signal delivered while in Junction syscall handler");

  if (unlikely(!context)) return;

  DeliverUserSignal(signo, info, sigframe);
}

void ThreadSignalHandler::EnqueueSignal(int signo, siginfo_t *info) {
  if (unlikely(pending_q_.size() >= kMaxQueuedRT)) {
    LOG_ONCE(ERR) << "Dropping RT signals";
    return;
  }

  pending_q_.emplace_back(*info);
  set_sig_pending(signo);
}

long usys_rt_sigaction(int sig, const struct k_sigaction *action,
                       struct k_sigaction *oact, size_t sigsetsize) {
  if (unlikely(sigsetsize != kSigSetSizeBytes)) return -EINVAL;
  myproc().get_signal_table().set_action(sig, action, oact);
  return 0;
}

long usys_rt_sigprocmask(int how, const sigset_t *nset, sigset_t *oset,
                         size_t sigsetsize) {
  if (unlikely(sigsetsize != kSigSetSizeBytes)) return -EINVAL;
  Status<void> ret = mythread().get_sighand().SigProcMask(
      how, reinterpret_cast<const kernel_sigset_t *>(nset),
      reinterpret_cast<kernel_sigset_t *>(oset));
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

long usys_sigaltstack(const stack_t *ss, stack_t *old_ss) {
  mythread().get_sighand().SigAltStack(ss, old_ss);
  return 0;
}

Status<void> InitSignal() {
  struct sigaction act;

  if (unlikely(sigemptyset(&act.sa_mask) != 0)) return MakeError(1);

  act.sa_sigaction = synchronous_signal_handler;
  act.sa_flags = SA_ONSTACK | SA_SIGINFO | SA_NODEFER;

  for (size_t sig = 1; sig <= 31; sig++) {
    if (!SIGINMASK(sig, kSigSynchronous)) continue;

    if (unlikely(base_sigaction(sig, &act, nullptr) != 0))
      return MakeError(errno);
  }

  // Replace Caladan sighandler with one that receives signals on
  // alternate stacks and transfers frames to the correct altstacks
  act.sa_sigaction = caladan_signal_handler;
  for (const auto &sig : {SIGUSR1, SIGUSR2}) {
    if (unlikely(base_sigaction(sig, &act, nullptr) != 0)) {
      return MakeError(errno);
    }
  }

  return {};
}

}  // namespace junction
