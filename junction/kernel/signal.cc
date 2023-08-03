
extern "C" {
#include <base/signal.h>
#include <base/thread.h>
#include <runtime/preempt.h>
#include <signal.h>
#include <ucontext.h>

#include "lib/caladan/runtime/defs.h"

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

namespace {

// Disable the altstack after delivering the signal.
inline constexpr uint32_t kSigStackAutoDisarm = (1U << 31);

template <typename... Args>
constexpr k_sigset_t MultiSignalMask(Args... args) {
  k_sigset_t mask = 0;
  for (const auto a : {args...}) mask |= SignalMask(a);
  return mask;
}

// Mask of signals that can only be handling in the kernel.
constexpr k_sigset_t kSignalKernelOnlyMask = MultiSignalMask(SIGKILL, SIGSTOP);
// Mask of signals that must be handled synchronously.
constexpr k_sigset_t kSignalSynchronousMask =
    MultiSignalMask(SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE);
// Mask of signals that have SI codes defined.
constexpr k_sigset_t kSignalSicodesMask = MultiSignalMask(
    SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGCHLD, SIGPOLL, SIGSYS);

//
// Default signal behaviors (specifies action when handler is SIG_DFL)
//

// Mask of signals that stop the process by default.
constexpr k_sigset_t kSignalStopMask =
    MultiSignalMask(SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU);
// Mask of signals that coredump by default.
constexpr k_sigset_t kSignalCoredumpMask =
    MultiSignalMask(SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGFPE, SIGSEGV, SIGBUS,
                    SIGSYS, SIGXCPU, SIGXFSZ);
// Mask of signals that are ignored by default.
constexpr k_sigset_t kSignalIgnoreMask =
    MultiSignalMask(SIGCONT, SIGCHLD, SIGWINCH, SIGURG);

enum class SignalAction : int {
  kStop,       // pause the thread on delivery
  kContinue,   // continue the thread if stopped
  kCoredump,   // terminate the process, and generate a core dump
  kTerminate,  // terminate the process
  kIgnore,     // do nothing
  kNormal,     // invoke the handler function normally
};

// ParseAction determines the appropriate action for a signal, considering the
// default behavior if applicable
constexpr SignalAction ParseAction(const k_sigaction &act, int sig) {
  // check if the signal has an action specified
  if (reinterpret_cast<uintptr_t>(act.handler) == 1)
    return SignalAction::kIgnore;
  else if (act.handler != kDefaultHandler)
    return SignalAction::kNormal;

  // otherwise lookup the default action
  if (sig == SIGCONT) return SignalAction::kContinue;
  if (SignalInMask(kSignalStopMask, sig)) return SignalAction::kStop;
  if (SignalInMask(kSignalCoredumpMask, sig)) return SignalAction::kCoredump;
  if (SignalInMask(kSignalIgnoreMask, sig)) return SignalAction::kIgnore;
  return SignalAction::kTerminate;
}

}  // namespace

inline void print_msg_abort(const char *msg) {
  syscall_write(2, msg, strlen(msg));
  syscall_exit(-1);
}

void MoveSigframeForImmediateUnwind(k_sigframe *sigframe, thread_tf &tf) {
  uint64_t rsp = sigframe->uc.uc_mcontext.rsp - kRedzoneSize;

  // In a Junction proc thread?
  if (get_uthread_specific()) {
    struct stack *stk = thread_self()->stack;
    if (!IsOnStack(rsp, *stk))
      rsp = reinterpret_cast<uint64_t>(&stk->usable[STACK_PTR_SIZE]);
  }

  // Transfer sigframe to the appropriate stack
  k_sigframe *new_frame = sigframe->CopyToStack(&rsp);
  new_frame->InvalidateAltStack();

  // Ensure the sigframe is immediately restored when this thread next runs
  tf.rip = reinterpret_cast<uintptr_t>(syscall_rt_sigreturn);
  tf.rsp = reinterpret_cast<uintptr_t>(&new_frame->uc);
}

// Signal handler for IOKernel sent signals (SIGUSR1 + SIGUSR2)
extern "C" __sighandler void caladan_signal_handler(int signo, siginfo_t *info,
                                                    void *context) {
  STAT(PREEMPTIONS)++;

  k_ucontext *uc = reinterpret_cast<k_ucontext *>(context);

  assert_on_runtime_stack();

  /* resume execution if preemption is disabled */
  if (!preempt_enabled()) {
    perthread_andi(preempt_cnt, 0x7fffffff);
    return;
  }

  /* we have received a signal on the runtime's stack but have not yet disabled
   * preemption */
  uint64_t ss = GetRuntimeStack();
  if (unlikely(uc->uc_mcontext.rsp <= ss &&
               uc->uc_mcontext.rsp > ss - RUNTIME_STACK_SIZE)) {
    perthread_andi(preempt_cnt, 0x7fffffff);
    return;
  }

  preempt_disable();

  k_sigframe *sigframe = container_of(uc, k_sigframe, uc);

  // set up unwinding from uthread stack
  MoveSigframeForImmediateUnwind(sigframe, thread_self()->tf);

  if (sigframe->info.si_signo == SIGUSR1)
    thread_finish_cede();
  else
    thread_finish_yield();

  std::unreachable();
}

std::optional<k_sigaction> ThreadSignalHandler::GetAction(int sig) {
  k_sigaction act = myproc().get_signal_table().get_action(sig, true);

  // is it a legacy signal that is already enqueued?
  if (sig <= kNumStandardSignals && is_sig_pending(sig)) return std::nullopt;

  // parse the type of signal action to perform
  SignalAction action = ParseAction(act, sig);
  if (action == SignalAction::kIgnore) return std::nullopt;

  // TODO: We don't support the other signal actions yet
  if (action != SignalAction::kNormal)
    print_msg_abort("program got fatal signal");

  return act;
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

void ThreadSignalHandler::DeliverKernelSigToUser(int signo, siginfo_t *info,
                                                 k_sigframe *sigframe) {
  assert_on_runtime_stack();

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
  void *fx_buf = sigframe->CopyXstateToStack(&rsp);

  // add a junction frame between xstate and ucontext
  rsp -= sizeof(JunctionSigframe);
  JunctionSigframe *jframe = reinterpret_cast<JunctionSigframe *>(rsp);
  jframe->type = SigframeType::kKernelSignal;
  jframe->magic = kJunctionFrameMagic;

  // copy ucontext, siginfo, etc
  k_sigframe *new_frame = sigframe->CopyToStack(&rsp, fx_buf);

  // fixup the frame
  TransformSigFrame(*new_frame, act);

  // disarm sigstack if needed
  if (switched_to_altstack && (ss.ss_flags & kSigStackAutoDisarm))
    DisableAltStack();

  // mask signals
  SigProcMask(SIG_BLOCK, &act.sa_mask, nullptr);

  if (unlikely(GetCfg().strace_enabled())) LogSignal(*info);

  // switch stacks and call sighandler
  thread_tf tf;
  tf.rsp = reinterpret_cast<uint64_t>(new_frame);
  tf.rip = reinterpret_cast<uint64_t>(act.handler);
  tf.rdi = static_cast<uint64_t>(signo);
  tf.rsi = reinterpret_cast<uint64_t>(&new_frame->info);
  tf.rdx = reinterpret_cast<uint64_t>(&new_frame->uc);
  __switch_and_preempt_enable(&tf);
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

  if (unlikely(!context)) print_msg_abort("signal delivered without context");

  preempt_disable();
  assert_on_runtime_stack();

  mythread().get_sighand().DeliverKernelSigToUser(signo, info, sigframe);

  // We return to this point if the signal is not able to be delivered to a
  // uthread. We need to unwind the kernel's trapframe, but cannot do so on this
  // non-preemption safe stack since we can't atomically enable preemption and
  // call rt_sigreturn. Instead, move the sigframe to a preemptable stack (ie
  // the uthread's stack) and then call sigreturn.

  LOG(INFO) << "Unwinding immediate, test me";
  thread_tf restore_tf;
  MoveSigframeForImmediateUnwind(sigframe, restore_tf);
  __switch_and_preempt_enable(&restore_tf);
  std::unreachable();
}

bool ThreadSignalHandler::EnqueueSignal(int signo, siginfo_t *info) {
  rt::SpinGuard g(lock_);

  if (unlikely(pending_q_.size() >= kMaxQueuedRT) &&
      signo >= kNumStandardSignals) {
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
    if (p->si_signo != signo) {
      p++;
      continue;
    }

    if (si.si_signo) {
      multiple = true;
      break;
    }

    si = *p;
    p = pending_q_.erase(p);
  }

  BUG_ON(!si.si_signo);
  if (!multiple) clear_sig_pending(signo);
  return si;
}

// Unwind a sigframe from a Junction process's thread.
// Note Linux's rt_sigreturn expects the sigframe to be on the stack.
// Our rt_sigreturn assembly target switches stacks and calls this function with
// the old rsp as an argument.
extern "C" [[noreturn]] void usys_rt_sigreturn(uint64_t rsp) {
  k_sigframe *sigframe = reinterpret_cast<k_sigframe *>(rsp - 8);
  JunctionSigframe *jframe =
      reinterpret_cast<JunctionSigframe *>(rsp - 8 + sizeof(*sigframe));
  ThreadSignalHandler &hand = mythread().get_sighand();

  assert_preempt_disabled();
  assert_on_runtime_stack();
  assert(rsp % 16 == 0);

  if (unlikely(jframe->magic != kJunctionFrameMagic))
    print_msg_abort("invalid stack frame used in rt_sigreturn");

  if (unlikely(GetCfg().strace_enabled())) LogSyscall("rt_sigreturn");

  // set blocked
  hand.SigProcMask(SIG_SETMASK, &sigframe->uc.mask, nullptr);

  // update altstack
  hand.SigAltStack(&sigframe->uc.uc_stack, nullptr);

  if (jframe->type == SigframeType::kKernelSignal) {
    // Clear sigaltstack and signal mask before using kernel to restore
    sigframe->InvalidateAltStack();
    sigframe->uc.mask = 0;

    thread_tf tf;
    tf.rsp = rsp;
    tf.rip = reinterpret_cast<uint64_t>(syscall_rt_sigreturn);
    __switch_and_preempt_enable(&tf);
  } else if (jframe->type == SigframeType::kJunctionDeferred) {
    __restore_tf_full_and_preempt_enable(jframe->restore_tf);
  }

  std::unreachable();
}

struct SigHandlerSetupArgs {
  k_sigaction act;
  siginfo_t *info;
  unsigned long prev_blocked;
  uint64_t rsp;
  thread_tf *caller_tf;
};

[[noreturn]] void SetupUserSigFrame(SigHandlerSetupArgs &args) {
  ThreadSignalHandler &hand = mythread().get_sighand();

  assert_preempt_disabled();

  uint64_t rsp = args.rsp ? args.rsp : args.caller_tf->rsp;

  // Use xsave's stack alignment even though we aren't using it here
  rsp = AlignDown(rsp, kXsaveAlignment);

  rsp -= sizeof(JunctionSigframe);
  JunctionSigframe *jframe = reinterpret_cast<JunctionSigframe *>(rsp);
  jframe->type = SigframeType::kJunctionDeferred;
  jframe->magic = kJunctionFrameMagic;
  jframe->restore_tf = args.caller_tf;

  rsp -= sizeof(k_sigframe);
  assert(rsp % 16 == 8);
  k_sigframe *kframe = reinterpret_cast<k_sigframe *>(rsp);
  kframe->pretcode = reinterpret_cast<char *>(args.act.restorer);
  kframe->uc.uc_flags = 0;
  kframe->uc.uc_link = 0;
  kframe->uc.uc_stack = hand.get_altstack();
  kframe->uc.mask = args.prev_blocked;
  kframe->uc.uc_mcontext.fpstate = nullptr;

  // TODO: anything to put in uc_mcontext?

  // disarm sigstack if needed
  if (args.rsp && (hand.get_altstack().ss_flags & kSigStackAutoDisarm))
    hand.DisableAltStack();

  // switch stacks and call sighandler
  thread_tf tf;
  tf.rsp = reinterpret_cast<uint64_t>(kframe);
  tf.rip = reinterpret_cast<uint64_t>(args.act.handler);
  tf.rdi = static_cast<uint64_t>(args.info->si_signo);
  tf.rsi = reinterpret_cast<uint64_t>(args.info);
  tf.rdx = reinterpret_cast<uint64_t>(&kframe->uc);
  __switch_and_preempt_enable(&tf);
  std::unreachable();
}

extern "C" [[noreturn]] void SetupUserSigFrameTrampoline(void *arg) {
  SigHandlerSetupArgs *args = reinterpret_cast<SigHandlerSetupArgs *>(arg);
  SetupUserSigFrame(*args);
}

thread_tf *SetupRestoreFrame(uint64_t *rsp, std::optional<long> rax) {
  *rsp -= sizeof(thread_tf);
  thread_tf &tf = *reinterpret_cast<thread_tf *>(*rsp);

  // perhaps need to use a kernel trap frame to get back to userland
  if (mythread().GetSyscallFrame() != nullptr) {
    // move the frame to the bottom of the signal handler stack
    k_sigframe *frame =
        reinterpret_cast<k_sigframe *>(mythread().GetSyscallFrame());
    k_sigframe *new_frame = frame->CopyToStack(rsp);

    mythread().SetSyscallFrame(nullptr);

    if (rax)
      new_frame->uc.uc_mcontext.rax = *rax;
    else
      new_frame->uc.uc_mcontext.rip -= 2;  // repeat the syscall instruction

    tf.rip = reinterpret_cast<uintptr_t>(syscall_rt_sigreturn);
    tf.rsp = reinterpret_cast<uintptr_t>(&new_frame->uc);
    return &tf;
  }

  const thread_tf &src_tf = thread_self()->junction_tf;

  tf.rbx = src_tf.rbx;
  tf.rbp = src_tf.rbp;
  tf.r12 = src_tf.r12;
  tf.r13 = src_tf.r13;
  tf.r13 = src_tf.r13;
  tf.r14 = src_tf.r14;
  tf.r15 = src_tf.r15;
  tf.rsp = src_tf.rsp;

  if (rax) {
    // syscall is done
    tf.rax = *rax;
    tf.rip = src_tf.rip;
  } else {
    tf.rax = src_tf.rax;
    // our golang target uses 7 bytes for indirect jump
    tf.rip = src_tf.rip - 7;
    // restore arg registers
    tf.rdi = src_tf.rdi;
    tf.rsi = src_tf.rsi;
    tf.rdx = src_tf.rdx;
    tf.r10 = src_tf.r10;
    tf.r8 = src_tf.r8;
    tf.r9 = src_tf.r9;
  }

  return &tf;
}

// May not return
void ThreadSignalHandler::RunPending(std::optional<long> rax) {
  if (!any_sig_pending()) return;

  std::optional<k_sigaction> act;
  siginfo_t sig;
  SigHandlerSetupArgs args;
  thread_tf tf_link;

  {
    rt::SpinGuard g(lock_);
    if (!any_sig_pending()) return;
    sig = PopNextSignal();
    act = GetAction(sig.si_signo);
    if (!act) return;
    args.prev_blocked = blocked_;
    SigProcMask(SIG_BLOCK, &act->sa_mask, nullptr);
  }

  if (unlikely(GetCfg().strace_enabled())) LogSignal(sig);

  const stack_t &ss = mythread().get_sighand().get_altstack();

  // Check if we are using the special per-uthread syscall stack
  bool on_syscall_stack = IsOnStack(*thread_self()->stack);
  uint64_t caller_rsp =
      on_syscall_stack ? thread_self()->junction_tf.rsp : GetRsp();

  if (act->wants_altstack() && has_altstack() && !IsOnStack(caller_rsp, ss))
    args.rsp = reinterpret_cast<uint64_t>(ss.ss_sp) + ss.ss_size;
  else if (on_syscall_stack)
    args.rsp = caller_rsp;
  else
    args.rsp = 0;

  args.act = *act;

  if (on_syscall_stack) {
    // we don't support re-entrant syscalls on the syscall stack, so we can't
    // leave state on this stack when running signals. Instead, arrange for the
    // signal return to bring execution back to the system call entry point,
    // either with a return value in rax or to repeat the system call.
    args.caller_tf = SetupRestoreFrame(&args.rsp, rax);

    args.rsp -= sizeof(siginfo_t);
    args.info = reinterpret_cast<siginfo_t *>(args.rsp);
    *args.info = sig;
  } else {
    // We will use the current stack to deliver the signal
    args.rsp = 0;
    // save current function state in tf_link so we can return to this function
    args.caller_tf = &tf_link;
  }

  mythread().in_syscall_ = false;

  preempt_disable();

  if (on_syscall_stack) {
    SetupUserSigFrame(args);
    std::unreachable();
  }

  __save_tf_switch(&tf_link, SetupUserSigFrameTrampoline,
                   perthread_read(runtime_stack),
                   reinterpret_cast<uint64_t>(&args));
  mythread().in_syscall_ = true;
}

long usys_rt_sigaction(int sig, const struct k_sigaction *iact,
                       struct k_sigaction *oact, size_t sigsetsize) {
  if (unlikely(sigsetsize != sizeof(k_sigset_t))) return -EINVAL;
  if (unlikely(SignalInMask(kSignalKernelOnlyMask, sig))) return -EINVAL;
  k_sigaction sa;
  if (iact) {
    sa = myproc().get_signal_table().exchange_action(sig, *iact);
  } else {
    sa = myproc().get_signal_table().get_action(sig);
  }
  if (oact) *oact = sa;
  return 0;
}

long usys_rt_sigprocmask(int how, const sigset_t *nset, sigset_t *oset,
                         size_t sigsetsize) {
  if (unlikely(sigsetsize != sizeof(k_sigset_t))) return -EINVAL;
  Status<void> ret = mythread().get_sighand().SigProcMask(
      how, reinterpret_cast<const k_sigset_t *>(nset),
      reinterpret_cast<k_sigset_t *>(oset));
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

long usys_sigaltstack(const stack_t *ss, stack_t *old_ss) {
  Status<void> ret = mythread().get_sighand().SigAltStack(ss, old_ss);
  if (unlikely(!ret)) return MakeCError(ret);
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
  if (unlikely(sigsetsize != sizeof(k_sigset_t))) return -EINVAL;
  k_sigset_t blocked_pending = mythread().get_sighand().get_blocked_pending();
  *reinterpret_cast<k_sigset_t *>(sig) = blocked_pending;
  return 0;
}

Status<void> InitSignal() {
  struct sigaction act;
  sigemptyset(&act.sa_mask);
  act.sa_sigaction = synchronous_signal_handler;
  act.sa_flags = SA_ONSTACK | SA_SIGINFO | SA_NODEFER;

  // Only synchronous signals need be delivered by the host kernel. Other
  // signal numbers will be emulated fully inside Junction.
  for (size_t sig = 1; sig <= kNumStandardSignals; sig++) {
    if (!SignalInMask(kSignalSynchronousMask, sig)) continue;
    if (unlikely(base_sigaction(sig, &act, nullptr) != 0))
      return MakeError(errno);
  }

  // Replace Caladan sighandler with one that receives signals on
  // alternate stacks and transfers frames to the correct altstacks
  act.sa_sigaction = caladan_signal_handler;
  for (auto sig : {SIGUSR1, SIGUSR2}) {
    if (unlikely(base_sigaction(sig, &act, nullptr) != 0)) {
      return MakeError(errno);
    }
  }

  return {};
}

}  // namespace junction
