
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
#include "junction/bindings/wait.h"
#include "junction/junction.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/sigframe.h"
#include "junction/kernel/usys.h"
#include "junction/syscall/strace.h"
#include "junction/syscall/syscall.h"

namespace junction {

namespace {

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

void __noinline print_msg_abort(const char *msg) {
  syscall_write(2, msg, strlen(msg));
  syscall_write(2, "\n", 1);
  syscall_exit(-1);
}

// override Caladan's implementation for interrupt checking
extern "C" bool thread_signal_pending(thread_t *th) {
  if (unlikely(!IsJunctionThread(th))) return false;

  return Thread::fromCaladanThread(th).needs_interrupt();
}

extern "C" bool sched_needs_signal_check(thread_t *th) {
  if (unlikely(!IsJunctionThread(th))) return false;

  return !Thread::fromCaladanThread(th).in_syscall();
}

void MoveSigframeForImmediateUnwind(k_sigframe *sigframe, thread_tf &tf) {
  uint64_t rsp = sigframe->uc.uc_mcontext.rsp - kRedzoneSize;

  // In a Junction proc thread?
  if (likely(IsJunctionThread())) {
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

// Switch to an altstack, if needed.
void FixRspAltstack(const DeliveredSignal &sig, uint64_t *rsp) {
  // do nothing if this sigaction doesn't use an altstack
  if (!sig.act.wants_altstack()) return;

  // check if the altstack was valid
  if (sig.ss.ss_flags & SS_DISABLE) return;

  // check if we are already on the altsack
  if (IsOnStack(*rsp, sig.ss)) return;

  // switch to the altstack
  *rsp = reinterpret_cast<uint64_t>(sig.ss.ss_sp) + sig.ss.ss_size;
}

// Handle a kick delivered by host OS signal (or UIPI in the future)
void HandleKick(k_sigframe *sigframe) {
  if (!IsJunctionThread()) return;

  Thread &th = mythread();

  if (th.in_syscall()) return;

  ThreadSignalHandler &hand = th.get_sighand();

  std::optional<DeliveredSignal> sig = hand.GetNextSignal();
  if (!sig) return;

  uint64_t rsp = sigframe->uc.uc_mcontext.rsp - kRedzoneSize;
  FixRspAltstack(*sig, &rsp);

  // Transfer kernel sigframe to the stack
  k_sigframe *new_frame = sigframe->CopyToStack(&rsp);
  new_frame->InvalidateAltStack();

  // trapframe to directly restore the kernel sigframe
  thread_tf restore_kernel;
  restore_kernel.rip = reinterpret_cast<uintptr_t>(syscall_rt_sigreturn);
  restore_kernel.rsp = reinterpret_cast<uintptr_t>(&new_frame->uc);

  thread_tf sighand_tf;
  hand.ApplySignals(*sig, &rsp, restore_kernel, sighand_tf);

  __switch_and_preempt_enable(&sighand_tf);
  std::unreachable();
}

// Signal handler for IOKernel sent signals (SIGUSR1 + SIGUSR2)
// Also handles SIGURG to deliver pending signals
extern "C" __sighandler void caladan_signal_handler(int signo, siginfo_t *info,
                                                    void *context) {
  STAT(PREEMPTIONS)++;

  k_ucontext *uc = reinterpret_cast<k_ucontext *>(context);

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
  assert_on_runtime_stack();

  k_sigframe *sigframe = container_of(uc, k_sigframe, uc);

  // Run signal handlers
  if (signo == SIGURG) {
    HandleKick(sigframe);

    // If we return to this point there is no signal to deliver, move to a
    // preemption-safe stack, reenable preemption, and then do an rt_sigreturn.
    thread_tf restore_tf;
    MoveSigframeForImmediateUnwind(sigframe, restore_tf);
    __switch_and_preempt_enable(&restore_tf);
    std::unreachable();
  }

  // restore runtime FS register
  SetFSBase(perthread_read(runtime_fsbase));

  // set up unwinding from uthread stack
  MoveSigframeForImmediateUnwind(sigframe, thread_self()->tf);

  if (signo == SIGUSR1)
    thread_finish_cede();
  else
    thread_finish_yield();

  std::unreachable();
}

// LTO seems to inline this...
[[nodiscard]] k_sigset_t ThreadSignalHandler::get_pending() const {
  return sig_q_.get_pending() | proc_->get_signal_queue().get_pending();
}

std::optional<k_sigaction> ThreadSignalHandler::GetAction(int sig) {
  // is it a legacy signal that is already enqueued?
  if (sig <= kNumStandardSignals && is_sig_pending(sig)) return std::nullopt;

  k_sigaction act = proc_->get_signal_table().get_action(sig, true);

  // parse the type of signal action to perform
  SignalAction action = ParseAction(act, sig);
  if (action == SignalAction::kIgnore) return std::nullopt;

  // TODO: We don't support the other signal actions yet
  if (action != SignalAction::kNormal)
    print_msg_abort("program got fatal signal");

  return act;
}

void ThreadSignalHandler::DeliverKernelSigToUser(int signo, siginfo_t *info,
                                                 k_sigframe *sigframe) {
  assert_on_runtime_stack();

  if (is_sig_blocked(signo)) {
    assert(info->si_signo == signo);
    EnqueueSignal(info);
    return;
  }

  std::optional<k_sigaction> tmp = GetAction(signo);
  if (!tmp) return;

  k_sigaction &act = *tmp;

  // Determine stack to use
  uint64_t rsp = sigframe->uc.uc_mcontext.rsp - kRedzoneSize;
  const stack_t &ss = get_altstack();
  if (act.wants_altstack() && has_altstack() && !IsOnStack(rsp, ss))
    rsp = reinterpret_cast<uint64_t>(ss.ss_sp) + ss.ss_size;

  // transfer the frame
  void *fx_buf = sigframe->CopyXstateToStack(&rsp);

  // add a junction frame between xstate and ucontext
  rsp -= sizeof(JunctionSigframe);
  JunctionSigframe *jframe = reinterpret_cast<JunctionSigframe *>(rsp);
  jframe->type = SigframeType::kKernelSignal;
  jframe->magic = kJunctionFrameMagic;

  // copy ucontext, siginfo, etc
  k_sigframe *new_frame = sigframe->CopyToStack(&rsp, fx_buf);

  // fix restorer
  new_frame->pretcode = reinterpret_cast<char *>(act.restorer);

  // fix altstack
  new_frame->uc.uc_stack = get_altstack();

  // disarm sigstack if needed
  if (ss.ss_flags & kSigStackAutoDisarm) DisableAltStack();

  // mask signals
  SigProcMask(SIG_BLOCK, &act.sa_mask, &new_frame->uc.mask);

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

  if (unlikely(!IsJunctionThread()))
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

bool SignalQueue::Enqueue(siginfo_t *info) {
  int signo = info->si_signo;

  if (unlikely(pending_q_.size() >= kMaxQueuedRT) &&
      signo >= kNumStandardSignals) {
    LOG_ONCE(ERR) << "Dropping RT signals";
    return false;
  }

  pending_q_.emplace_back(*info);
  set_sig_pending(signo);
  return true;
}

siginfo_t SignalQueue::Pop(k_sigset_t blocked) {
  std::optional<siginfo_t> sig = GetSignal(
      blocked, [](siginfo_t &) { return true; }, true);
  BUG_ON(!sig);
  return *sig;
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
  } else if (jframe->type == SigframeType::kJunctionTf) {
    __restore_tf_full_and_preempt_enable(jframe->restore_tf);
  }

  std::unreachable();
}

// Pushes a trapframe (@src) on the stack at @rsp, returns a pointer to the
// stack trapframe.
thread_tf *PushTrapFrameToStack(uint64_t *rsp, const thread_tf &src) {
  *rsp -= sizeof(thread_tf);
  thread_tf *new_tf = reinterpret_cast<thread_tf *>(*rsp);
  *new_tf = src;
  return new_tf;
}

// Find next signal pending in either the thread and proc siqueues
bool ThreadSignalHandler::PopSigInfo(siginfo_t *dst_sig) {
  if (sig_q_.get_pending(blocked_)) {
    rt::SpinGuard g(sig_q_);
    if (sig_q_.get_pending(blocked_)) {
      *dst_sig = sig_q_.Pop(blocked_);
      return true;
    }
  }

  SignalQueue &shared_q = proc_->get_signal_queue();
  if (shared_q.get_pending(blocked_)) {
    rt::SpinGuard g(shared_q);
    if (shared_q.get_pending(blocked_)) {
      *dst_sig = shared_q.Pop(blocked_);
      return true;
    }
  }

  return false;
}

// Find next actionable signal
std::optional<DeliveredSignal> ThreadSignalHandler::GetNextSignal() {
  DeliveredSignal sig;

  if (unlikely(is_sig_pending(SIGKILL))) {
    usys_exit(0);
    std::unreachable();
  }

  while (true) {
    if (!PopSigInfo(&sig.info)) return std::nullopt;
    std::optional<k_sigaction> act = GetAction(sig.info.si_signo);

    // try again if signal is ignored
    if (!act) continue;

    sig.act = *act;
    break;
  }

  // Record the altstack, disable if needed
  sig.ss = get_altstack();
  if (sig.ss.ss_flags & kSigStackAutoDisarm) DisableAltStack();

  // Apply blocked signal mask
  unsigned long to_block = sig.act.sa_flags;
  if (!sig.act.is_nodefer()) to_block |= SignalMask(sig.info.si_signo);
  SigProcMask(SIG_BLOCK, &to_block, &sig.prev_blocked);

  if (unlikely(GetCfg().strace_enabled())) LogSignal(sig.info);

  return sig;
}

// Setup @signal on the stack given by @rsp (may be switched). @prev_frame is
// copied to the stack, and @new_frame is set to jump to the signal handler
void PushUserSigFrame(const DeliveredSignal &signal, uint64_t *rsp,
                      const thread_tf &prev_frame, thread_tf &new_frame) {
  // Fix RSP to ensure we are on the appropriate stack
  FixRspAltstack(signal, rsp);

  // Use xsave's stack alignment even though we aren't using it here
  *rsp = AlignDown(*rsp, kXsaveAlignment);

  // Push siginfo
  *rsp -= sizeof(siginfo_t);
  siginfo_t *info = reinterpret_cast<siginfo_t *>(*rsp);
  *info = signal.info;

  // Push the restore frame to the stack
  thread_tf *restore_tf = PushTrapFrameToStack(rsp, prev_frame);

  // Push metadata using JunctionSigframe
  *rsp -= sizeof(JunctionSigframe);
  JunctionSigframe *jframe = reinterpret_cast<JunctionSigframe *>(*rsp);
  jframe->type = SigframeType::kJunctionTf;
  jframe->magic = kJunctionFrameMagic;
  jframe->restore_tf = restore_tf;

  // Push a fake kernel sigframe
  *rsp -= sizeof(k_sigframe);
  assert(*rsp % 16 == 8);
  k_sigframe *kframe = reinterpret_cast<k_sigframe *>(*rsp);
  kframe->pretcode = reinterpret_cast<char *>(signal.act.restorer);
  kframe->uc.uc_flags = 0;
  kframe->uc.uc_link = 0;
  kframe->uc.uc_stack = signal.ss;
  kframe->uc.mask = signal.prev_blocked;
  kframe->uc.uc_mcontext.fpstate = nullptr;

  // Prepare a trapframe to jump to this signal handler/stack
  new_frame.rsp = reinterpret_cast<uint64_t>(kframe);
  new_frame.rip = reinterpret_cast<uint64_t>(signal.act.handler);
  new_frame.rdi = static_cast<uint64_t>(signal.info.si_signo);
  new_frame.rsi = reinterpret_cast<uint64_t>(info);
  new_frame.rdx = reinterpret_cast<uint64_t>(&kframe->uc);
}

// Push first signal onto the stack, and then chain any following signals
void ThreadSignalHandler::ApplySignals(const DeliveredSignal &first_signal,
                                       uint64_t *rsp,
                                       const thread_tf &restore_tf,
                                       thread_tf &sighand_tf) {
  PushUserSigFrame(first_signal, rsp, restore_tf, sighand_tf);

  while (true) {
    std::optional<DeliveredSignal> d = GetNextSignal();
    if (!d) break;

    PushUserSigFrame(*d, rsp, sighand_tf, sighand_tf);
  }
}

[[noreturn]] void ThreadSignalHandler::ApplySignalsAndExit(
    const DeliveredSignal &first_signal, uint64_t rsp,
    const thread_tf &restore_tf) {
  thread_tf sighand_tf;  // frame used to exit to signal handler

  ApplySignals(first_signal, &rsp, restore_tf, sighand_tf);
  mythread().get_sighand().RestoreBlocked();

  while (true) {
    // no more signals, try to exit to user mode
    preempt_disable();
    mythread().set_in_syscall(false);
    barrier();
    if (!any_sig_pending()) {
      __switch_and_preempt_enable(&sighand_tf);
      std::unreachable();
    }

    // a signal slipped in, handle it and try again
    mythread().set_in_syscall(true);
    preempt_enable();

    std::optional<DeliveredSignal> sig = GetNextSignal();
    if (sig) ApplySignals(*sig, &rsp, sighand_tf, sighand_tf);
  }
}

struct SigHandlerSetupArgs {
  DeliveredSignal first_sig;
  thread_tf restore_tf;
};

extern "C" [[noreturn]] void ApplySignalsTrampoline(void *arg) {
  SigHandlerSetupArgs &args = *reinterpret_cast<SigHandlerSetupArgs *>(arg);

  // use the stack we just came from for signals, maybe
  uint64_t rsp = args.restore_tf.rsp;
  FixRspAltstack(args.first_sig, &rsp);

  mythread().get_sighand().ApplySignalsAndExit(args.first_sig, rsp,
                                               args.restore_tf);
}

// Prepare a trap frame that returns execution to rt_sigreturn to unwind a
// syscall signal
void SetupRestoreSignalEntry(uint64_t *rsp, std::optional<long> rax,
                             thread_tf *tf) {
  assert(mythread().GetSyscallFrame() != nullptr);

  // move the frame to the bottom of the signal handler stack
  k_sigframe *frame =
      reinterpret_cast<k_sigframe *>(mythread().GetSyscallFrame());
  k_sigframe *new_frame = frame->CopyToStack(rsp);

  mythread().SetSyscallFrame(nullptr);

  if (rax)
    new_frame->uc.uc_mcontext.rax = *rax;
  else
    new_frame->uc.uc_mcontext.rip -= 2;  // repeat the syscall instruction

  tf->rip = reinterpret_cast<uintptr_t>(syscall_rt_sigreturn);
  tf->rsp = reinterpret_cast<uintptr_t>(&new_frame->uc);
}

// Prepare a trap frame that returns to a Golang syscall entry site
void SetupRestoreGolang(std::optional<long> rax, thread_tf *tf) {
  if (rax) {
    // syscall is done
    tf->rax = *rax;
  } else {
    // our golang target uses 7 bytes for indirect jump
    tf->rip -= 7;
  }
}

// Called by the Caladan scheduler to deliver signals to a thread that is being
// scheduled in and is not in a syscall (perhaps it was preempted).
extern "C" void deliver_signals_jmp_thread(thread_t *th) {
  assert(sched_needs_signal_check(th));
  assert(thread_signal_pending(th));
  assert_preempt_disabled();
  assert_on_runtime_stack();
  assert(th->thread_running);

  ThreadSignalHandler &hand = Thread::fromCaladanThread(th).get_sighand();

  thread_tf &tf = thread_self()->tf;

  uint64_t rsp = tf.rsp;

  while (true) {
    std::optional<DeliveredSignal> d = hand.GetNextSignal();
    if (!d) break;

    PushUserSigFrame(*d, &rsp, tf, tf);
  }
}

void ThreadSignalHandler::RunPending(std::optional<long> rax) {
  std::optional<DeliveredSignal> sig = GetNextSignal();
  if (!sig) return;

  // we don't support re-entrant syscalls on the syscall stack, so we can't
  // leave state on this stack when running signals. Instead, arrange for the
  // signal return to bring execution back to the system call entry point,
  // either with a return value in rax or to repeat the system call.
  if (IsOnStack(GetSyscallStack())) {
    // find the stack that will be used for the first signal
    uint64_t rsp = thread_self()->junction_tf.rsp;
    FixRspAltstack(*sig, &rsp);

    thread_tf tmp;  // for signal syscall entry
    thread_tf *restore_tf;

    // setup restore frames
    if (mythread().GetSyscallFrame() != nullptr) {
      restore_tf = &tmp;
      SetupRestoreSignalEntry(&rsp, rax, restore_tf);
    } else {
      restore_tf = &thread_self()->junction_tf;
      SetupRestoreGolang(rax, restore_tf);
    }

    ApplySignalsAndExit(*sig, rsp, *restore_tf);
    std::unreachable();
  } else {
    SigHandlerSetupArgs args;
    args.first_sig = *sig;

    __save_tf_switch(&args.restore_tf, ApplySignalsTrampoline,
                     reinterpret_cast<void *>(GetSyscallStackBottom()),
                     reinterpret_cast<uint64_t>(&args));

    // when we return to this point, we re-enter the syscall
    mythread().set_in_syscall(true);
  }
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
  Status<void> ret = myproc().SignalThread(tid, info);
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

long usys_rt_sigpending(sigset_t *sig, size_t sigsetsize) {
  if (unlikely(sigsetsize != sizeof(k_sigset_t))) return -EINVAL;
  k_sigset_t blocked_pending = mythread().get_sighand().get_blocked_pending();
  *reinterpret_cast<k_sigset_t *>(sig) = blocked_pending;
  return 0;
}

int usys_rt_sigtimedwait(const sigset_t *set, siginfo_t *info,
                         const struct timespec *ts, size_t sigsetsize) {
  if (unlikely(sigsetsize != sizeof(k_sigset_t))) return -EINVAL;

  ThreadSignalHandler &hand = mythread().get_sighand();
  rt::Spin &lock = mythread().get_waker_lock();
  std::optional<Duration> timeout;
  if (ts) timeout = Duration(*ts);

  unsigned long oset, mask = ~*reinterpret_cast<const k_sigset_t *>(set);
  hand.SigProcMask(SIG_SETMASK, &mask, &oset);

  if (!hand.any_sig_pending() && (!timeout || !timeout->IsZero())) {
    rt::ThreadWaker w;
    WakeOnTimeout timed_out(lock, w, timeout);
    rt::SpinGuard g(lock);
    WaitInterruptible(lock, w,
                      [&timed_out] { return static_cast<bool>(timed_out); });
  }

  siginfo_t tmp;
  if (!info) info = &tmp;
  bool found = hand.PopSigInfo(info);
  hand.SigProcMask(SIG_SETMASK, &oset, nullptr);
  if (found) return info->si_signo;

  return -EINTR;  // TODO: ERESTARTX?
}

int usys_rt_sigsuspend(const sigset_t *set, size_t sigsetsize) {
  if (unlikely(sigsetsize != sizeof(k_sigset_t))) return -EINVAL;

  const k_sigset_t *mask = reinterpret_cast<const k_sigset_t *>(set);

  ThreadSignalHandler &hand = mythread().get_sighand();
  hand.SaveBlocked();
  hand.SigProcMask(SIG_SETMASK, mask, nullptr);

  {
    rt::Spin &lock = mythread().get_waker_lock();
    rt::ThreadWaker w;
    rt::SpinGuard g(lock);
    WaitInterruptible(lock, w);
  }

  return -EINTR;  // TODO: Should be ERESTARTNOHAND
}

long usys_pause() {
  rt::ThreadWaker w;
  rt::Spin &lock = mythread().get_waker_lock();
  rt::SpinGuard g(lock);
  WaitInterruptible(lock, w);
  return -EINTR;  // TODO: Should be ERESTARTNOHAND
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
  for (auto sig : {SIGUSR1, SIGUSR2, SIGURG}) {
    if (unlikely(base_sigaction(sig, &act, nullptr) != 0)) {
      return MakeError(errno);
    }
  }

  return {};
}

}  // namespace junction
