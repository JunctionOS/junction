
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
#include "junction/kernel/sigframe.h"
#include "junction/kernel/usys.h"
#include "junction/syscall/strace.h"
#include "junction/syscall/syscall.h"

namespace junction {

inline void print_msg_abort(const char *msg) {
  std::ignore = write(2, msg, strlen(msg));
  syscall_exit(-1);
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
      sigframe->CopyToStack(reinterpret_cast<uint64_t>(rsp));
  new_frame->InvalidateAltStack();

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
extern "C" __sighandler void caladan_signal_handler(int signo, siginfo_t *info,
                                                    void *context) {
  STAT(PREEMPTIONS)++;

  /* resume execution if preemption is disabled */
  if (!preempt_enabled()) {
    perthread_andi(preempt_cnt, 0x7fffffff);
    return;
  }

  preempt_disable();

  // cache a pointer to the sigframe in the struct thread
  k_ucontext *uc = reinterpret_cast<k_ucontext *>(context);
  k_sigframe *sigframe = container_of(uc, k_sigframe, uc);
  thread_self()->stashed_sigframe = sigframe;

  jmp_runtime_nosave(DeliverCaladanSignal);
}

// Unwind a sigframe from a Junction process's thread.
// Note Linux's rt_sigreturn expects the sigframe to be on the stack.
// Our rt_sigreturn assembly target switches stacks and calls this function with
// the old rsp as an argument.
extern "C" [[noreturn]] void usys_rt_sigreturn(uint64_t rsp) {
  k_sigframe *sigframe = reinterpret_cast<k_sigframe *>(rsp - 8);
  ThreadSignalHandler &hand = mythread().get_sighand();

  if (unlikely(GetCfg().strace_enabled())) LogSyscall("rt_sigreturn");

  // set blocked
  hand.SigProcMask(SIG_SETMASK, &sigframe->uc.mask, nullptr);

  // update altstack
  hand.SigAltStack(&sigframe->uc.uc_stack, nullptr);

  // Clear sigaltstack and signal mask before using kernel to restore
  sigframe->InvalidateAltStack();
  sigframe->uc.mask = 0;

  // switch stack back to rsp and jmp to the real rt_sigreturn
  asm volatile(
      "movq %0, %%rsp\n\t"
      "jmp syscall_rt_sigreturn"
      :
      : "r"(rsp)
      : "memory");

  std::unreachable();
}

// Sigframes delivered to Junction procs need some fields replaced
void ThreadSignalHandler::TransformSigFrame(k_sigframe &sigframe,
                                            const k_sigaction &act) const {
  // fix restorer
  sigframe.pretcode = reinterpret_cast<char *>(act.restorer);

  // fix blocked signal mask
  sigframe.uc.mask = get_blocked_mask();

  // fix altstack
  sigframe.uc.uc_stack = get_altstack();
}

std::optional<k_sigaction> ThreadSignalHandler::GetAction(int signo) {
  k_sigaction act = myproc().get_signal_table().get_action(signo);

  // is it a legacy signal that is already enqueued?
  if (signo < kSigRtMin && is_sig_pending(signo)) return std::nullopt;

  // is the handler set to SIG_IGN?
  if (act.is_ignored(signo)) return std::nullopt;

  // TODO: better crash?
  if (act.is_default() && CheckSignalInMask(signo, kSigDefaultCrash))
    panic("program got fatal signal");

  if (act.is_oneshot()) {
    std::optional<k_sigaction> tmp =
        myproc().get_signal_table().atomic_reset_oneshot(signo);
    if (!tmp) return std::nullopt;
    act = *tmp;
  }

  return act;
}

void ThreadSignalHandler::DeliverQueuedSigToUser(siginfo_t *info,
                                                 k_sigaction &act) {
  if (unlikely(GetCfg().strace_enabled())) LogSignal(*info);

  mythread().in_syscall_ = false;

  // For now, we cheat and just invoke the signal handler on this stack.
  // Try passing a nullptr for context and see if anyone cares!
  act.handler(info->si_signo, info, nullptr);

  mythread().in_syscall_ = true;
}

void ThreadSignalHandler::DeliverKernelSigToUser(int signo, siginfo_t *info,
                                                 k_sigframe *sigframe) {
  if (is_sig_blocked(signo)) {
    EnqueueSignal(signo, info);
    return;
  }

  std::optional<k_sigaction> tmp = GetAction(signo);
  if (!tmp) return;

  k_sigaction &act = *tmp;

  // Determine stack to use
  uint64_t rsp = sigframe->uc.uc_mcontext.rsp - kRedzoneSize;
  bool switched_to_altstack = false;
  const stack_t &ss = get_altstack();
  if (act.wants_altstack() && has_altstack() && !IsOnStack(rsp, ss)) {
    switched_to_altstack = true;
    rsp = reinterpret_cast<uint64_t>(ss.ss_sp) + ss.ss_size;
  }

  // transfer the frame
  k_sigframe *new_frame = sigframe->CopyToStack(rsp);

  // fixup the frame
  TransformSigFrame(*new_frame, act);

  // disarm sigstack if needed
  if (switched_to_altstack && (ss.ss_flags & kSigStackAutoDisarm))
    DisableAltStack();

  // mask signals
  SigProcMask(SIG_BLOCK, &act.sa_mask, nullptr);

  if (unlikely(GetCfg().strace_enabled())) LogSignal(*info);

  // switch stacks and call sighandler
  asm volatile(
      "movq %0, %%rsp\n\t"
      "jmpq *%1"
      :
      : "r"(new_frame), "r"(act.handler), "D"(signo), "S"(&new_frame->info),
        "d"(&new_frame->uc)
      : "memory");

  std::unreachable();
}

// Signal handler for synchronous fault signals generated by user code. We
// don't expect there to be recursive signals.
extern "C" __sighandler void synchronous_signal_handler(int signo,
                                                        siginfo_t *info,
                                                        void *context) {
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

  mythread().get_sighand().DeliverKernelSigToUser(signo, info, sigframe);
}

bool ThreadSignalHandler::EnqueueSignal(int signo, siginfo_t *info) {
  rt::SpinGuard g(lock_);

  if (unlikely(pending_q_.size() >= kMaxQueuedRT) && signo >= kSigRtMin) {
    LOG_ONCE(ERR) << "Dropping RT signals";
    return false;
  }

  assert(info->si_signo == signo);
  pending_q_.emplace_back(*info);
  set_sig_pending(signo);

  return !is_sig_blocked(signo);
}

siginfo_t ThreadSignalHandler::PopNextSignal() {
  assert(lock_.IsHeld());

  if (unlikely(is_sig_pending(SIGKILL))) {
    lock_.Unlock();
    usys_exit(0);
    std::unreachable();
  }

  int signo = __builtin_ffsl(pending_ & ~blocked_);
  BUG_ON(signo <= 0);

  siginfo_t si;
  si.si_signo = 0;
  bool multiple = false;

  for (auto p = pending_q_.begin(); p != pending_q_.end();) {
    if (p->sig.si_signo != signo) {
      p++;
      continue;
    }

    if (si.si_signo) {
      multiple = true;
      break;
    }

    si = p->sig;
    p = pending_q_.erase(p);
  }

  BUG_ON(!si.si_signo);
  if (!multiple) clear_sig_pending(signo);
  return si;
}

void ThreadSignalHandler::RunPending() {
  std::optional<k_sigaction> act;
  siginfo_t sig;

  unsigned long prev_blocked;

  while (any_sig_pending()) {
    {
      rt::SpinGuard g(lock_);
      sig = PopNextSignal();
      act = GetAction(sig.si_signo);
      if (!act) continue;
      prev_blocked = blocked_;
      SigProcMask(SIG_BLOCK, &act->sa_mask, nullptr);
    }
    DeliverQueuedSigToUser(&sig, *act);
    SigProcMask(SIG_SETMASK, &prev_blocked, nullptr);
  }
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

long usys_tgkill(pid_t tgid, pid_t tid, int sig) {
  // TODO: support interprocess signals if needed
  if (tgid != myproc().get_pid()) return -EPERM;
  Status<void> ret = myproc().SignalThread(tid, sig);
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

long usys_rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *info) {
  // TODO: support interprocess signals if needed
  if (tgid != myproc().get_pid()) return -EPERM;
  info->si_signo = sig;
  Status<void> ret = myproc().SignalThread(tid, sig, info);
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

long usys_rt_sigpending(sigset_t *sig, size_t sigsetsize) {
  if (unlikely(sigsetsize != kSigSetSizeBytes)) return -EINVAL;
  kernel_sigset_t blocked_pending =
      mythread().get_sighand().get_blocked_pending();
  *reinterpret_cast<kernel_sigset_t *>(sig) = blocked_pending;
  return 0;
}

Status<void> InitSignal() {
  struct sigaction act;

  if (unlikely(sigemptyset(&act.sa_mask) != 0)) return MakeError(1);

  act.sa_sigaction = synchronous_signal_handler;
  act.sa_flags = SA_ONSTACK | SA_SIGINFO | SA_NODEFER;

  for (size_t sig = 1; sig <= 31; sig++) {
    if (!CheckSignalInMask(sig, kSigSynchronous)) continue;

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
