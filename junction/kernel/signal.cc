
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
#include "junction/snapshot/proc.h"
#include "junction/syscall/strace.h"
#include "junction/syscall/syscall.h"
#include "junction/syscall/systbl.h"

namespace junction {

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

// A signal handler that can be injected into a program to cleanly kill it
extern "C" void SigKillHandler(int, siginfo_t *, void *);
asm(R"(
  .globl SigKillHandler
  .type SigKillHandler, @function
  SigKillHandler:

  movl $231, %eax;  // __NR_exit_group
  addl $128, %edi; // exit code: 128 + signo

  subq $8, %rsp
  call junction_fncall_enter
  nop
)");

static k_sigaction SigKillAction = {
    .handler = SigKillHandler,
    .sa_flags = SA_ONSTACK | SA_RESTART | SA_NODEFER,
    .sa_mask = ~0UL,  // all signals masked
};

void __noinline print_msg_abort(const char *msg) {
  const char *m = "Aborting on signal: ";
  syscall_write(2, m, strlen(m));
  syscall_write(2, msg, strlen(msg));
  syscall_write(2, "\n", 1);
  syscall_exit(-1);
}

// A kernel signal (trapframe in @sigframe) was delivered while a Junction
// thread was running. This function moves the sigframe to the Junction thread's
// syscall stack so it can be restored with preemption enabled.
void MoveSigframeToJunctionThread(k_sigframe *sigframe, thread_tf &tf) {
  assert(IsJunctionThread());
  Thread &myth = mythread();
  stack &syscall_stack = *myth.GetCaladanThread()->stack;

  uint64_t rsp = sigframe->uc.uc_mcontext.rsp - kRedzoneSize;
  bool on_syscall_stack = IsOnStack(rsp, syscall_stack);
  bool in_syscall = myth.in_syscall();

  // We are going to unwind this sigframe by moving it to the syscall stack
  // and then re-enabling preemption. Because the syscall stack does not support
  // re-entrant system calls, care must be taken to ensure that user-level
  // signal delivery does not occur on this stack. Normally this is handled by
  // setting the in_syscall flag while using the stack. If the thread is not
  // currently "in_syscall", mark it as such to prevent future signal handlers
  // from running on the syscall stack.

  // There is a race that may occur when a stack-switching system call is
  // returning: it may clear the in_syscall flag before leaving the stack.
  // In this case, the trapframe that was saved at syscall entry (and updated
  // before returning) will be our target restore trapframe instead of the
  // provided k_sigframe.
  if (unlikely(!in_syscall && on_syscall_stack)) {
    if (myth.get_syscall_source() == SyscallEntry::kSyscallTrapSysStack) {
      tf.rsp = reinterpret_cast<uint64_t>(&myth.GetSyscallFrame()->uc);
      tf.rip = reinterpret_cast<uint64_t>(__syscall_trap_exit_loop);
    } else {
      tf.rsp = reinterpret_cast<uint64_t>(&myth.get_fncall_regs());
      tf.rip = reinterpret_cast<uint64_t>(__fncall_return_exit_loop);
    }
    assert(IsOnStack(tf.rsp, syscall_stack));
    return;
  }

  if (!on_syscall_stack)
    rsp = reinterpret_cast<uint64_t>(&syscall_stack.usable[STACK_PTR_SIZE]);

  // copy the sigframe over
  k_sigframe *new_frame = sigframe->CopyToStack(&rsp);
  new_frame->InvalidateAltStack();

  myth.SetSyscallFrame(new_frame);
  myth.set_in_syscall(true);

  tf.rip = reinterpret_cast<uint64_t>(__syscall_trap_exit_loop);
  tf.rsp = reinterpret_cast<uintptr_t>(&new_frame->uc);
}

// Move a @sigframe to the stack @rsp.
void MoveSigframeForImmediateUnwind(uint64_t rsp, k_sigframe *sigframe,
                                    thread_tf &tf) {
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

void PushUserSigFrame(const DeliveredSignal &signal, uint64_t *rsp,
                      const thread_tf &prev_frame, thread_tf &new_frame);

// Handle a kick delivered by host OS signal (or UIPI in the future)
void HandleKick(k_sigframe *sigframe) {
  assert(IsJunctionThread());

  Thread &th = mythread();

  // The caller will ensure that user code will first check for signals before
  // restoring the sigframe, which the situation where the user code is
  // returning from a syscall but is still on the syscall stack .
  if (th.in_syscall() || unlikely(IsOnStack(GetSyscallStack()))) return;

  ThreadSignalHandler &hand = th.get_sighand();
  std::optional<DeliveredSignal> sig = hand.GetNextSignal();
  if (!sig) return;

  // Get current rsp
  uint64_t rsp = sigframe->uc.uc_mcontext.rsp - kRedzoneSize;
  FixRspAltstack(*sig, &rsp);

  thread_tf restore_tf;
  // Push the sigframe to the stack; rip/rsp are set in restore_tf.
  MoveSigframeForImmediateUnwind(rsp, sigframe, restore_tf);

  // Push the first signal to the stack.
  PushUserSigFrame(*sig, &rsp, restore_tf, restore_tf);

  // Add subsequent signals.
  while (true) {
    sig = hand.GetNextSignal();
    if (!sig) break;
    PushUserSigFrame(*sig, &rsp, restore_tf, restore_tf);
  }

  __switch_and_preempt_enable(&restore_tf);
  std::unreachable();
}

// Signal handler for IOKernel sent signals (SIGUSR1 + SIGUSR2)
// Also handles SIGURG to deliver pending signals
extern "C" void caladan_signal_handler(int signo, siginfo_t *info,
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

  bool is_junction_thread = IsJunctionThread();

  // Run signal handlers if needed
  if (signo == SIGURG && is_junction_thread) {
    // Try to deliver signals.
    HandleKick(sigframe);

    // If we return to this point there is no signal to deliver, move to a
    // preemption-safe stack, reenable preemption, and then do an rt_sigreturn.
    thread_tf restore_tf;
    MoveSigframeToJunctionThread(sigframe, restore_tf);
    __switch_and_preempt_enable(&restore_tf);
    std::unreachable();
  }

  // restore runtime FS register
  SetFSBase(perthread_read(runtime_fsbase));

  // set up unwinding from uthread stack
  if (is_junction_thread)
    MoveSigframeToJunctionThread(sigframe, thread_self()->tf);
  else
    MoveSigframeForImmediateUnwind(sigframe->uc.uc_mcontext.rsp - kRedzoneSize,
                                   sigframe, thread_self()->tf);

  if (signo == SIGUSR1)
    thread_finish_cede();
  else
    thread_finish_yield();

  std::unreachable();
}

std::optional<k_sigaction> ThreadSignalHandler::GetAction(int sig) {
  k_sigaction act =
      this_thread().get_process().get_signal_table().get_action(sig, true);

  // parse the type of signal action to perform
  SignalAction action = ParseAction(act, sig);

  switch (action) {
    case SignalAction::kNormal:
      return act;
    case SignalAction::kIgnore:
    case SignalAction::kContinue:
      return std::nullopt;
    case SignalAction::kStop:
      // TODO: add support for stopping
    case SignalAction::kTerminate:
    case SignalAction::kCoredump:
      return SigKillAction;
  }

  std::unreachable();
}

[[noreturn]] void ThreadSignalHandler::DeliverKernelSigToUser(
    int signo, siginfo_t *info, k_sigframe *sigframe) {
  assert_on_runtime_stack();

  // TODO: just kill the Process
  if (is_sig_blocked(signo)) print_msg_abort("synchronous signal blocked");

  std::optional<k_sigaction> tmp = GetAction(signo);

  // synchronous signal kills program if no action is specified
  k_sigaction &act = tmp ? *tmp : SigKillAction;

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

  // Mask signals. Because this signal delivery occurs outside of a syscall, we
  // don't need to worry about restoring a saved mask.
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

void ThreadSignalHandler::Snapshot(ThreadMetadata &s) const & {
  sig_q_.Snapshot(s);
  s.SetSignalHandlerBlocked(blocked_);
  if (saved_blocked_) {
    s.SetSignalHandlerSavedBlocked(*saved_blocked_);
  }

  s.SetSignalHandlerAltStack(sigaltstack_);
}
void ThreadSignalHandler::Restore(ThreadMetadata const &tm) {
  sig_q_.Restore(tm);
  blocked_ = tm.GetSignalHandlerBlocked();
  saved_blocked_ = tm.GetSignalHandlerSavedBlocked();
  sigaltstack_ = tm.GetSignalHandlerAltStack();
}

// Signal handler for synchronous fault signals generated by user code. We
// don't expect there to be recursive signals.
extern "C" void synchronous_signal_handler(int signo, siginfo_t *info,
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
  std::unreachable();
}

std::optional<siginfo_t> SignalQueue::Pop(k_sigset_t blocked,
                                          bool remove = true) {
  assert(IsHeld());
  int signo = __builtin_ffsl(pending_ & ~blocked);
  if (signo <= 0) return std::nullopt;

  siginfo_t si;
  si.si_signo = 0;
  size_t signo_count = 0;

  for (auto p = pending_q_.begin(); p != pending_q_.end();) {
    if (p->si_signo != signo) {
      p++;
      continue;
    }

    signo_count++;

    if (!si.si_signo) {
      if (!remove) return *p;
      si = *p;
      p = pending_q_.erase(p);
    } else if (signo_count > 1) {
      break;
    }
  }

  if (!si.si_signo) return std::nullopt;
  if (signo_count == 1) clear_sig_pending(signo);
  return si;
}

bool SignalQueue::Enqueue(const siginfo_t &info) {
  int signo = info.si_signo;

  if (unlikely(pending_q_.size() >= kMaxQueuedRT) &&
      signo >= kNumStandardSignals) {
    LOG_ONCE(ERR) << "Dropping RT signals";
    return false;
  }

  pending_q_.emplace_back(info);
  set_sig_pending(signo);
  return true;
}

void SignalQueue::Snapshot(ProcessMetadata &snapshot) const & {
  snapshot.SetSignalQueuePending(pending_);
  snapshot.ReserveNPendingSignals(pending_q_.size());
  for (auto sig : pending_q_) {
    snapshot.AddPendingSignal(sig);
  }
}

void SignalQueue::Snapshot(ThreadMetadata &snapshot) const & {
  snapshot.SetSignalQueuePending(pending_);
  snapshot.ReserveNPendingSignals(pending_q_.size());
  for (auto sig : pending_q_) {
    snapshot.AddPendingSignal(sig);
  }
}

void SignalQueue::Restore(ProcessMetadata const &pm) {
  pending_ = pm.GetSignalQueuePending();
  for (auto const &sig : pm.GetPendingSignals()) {
    Enqueue(sig);
  }
}

void SignalQueue::Restore(ThreadMetadata const &tm) {
  pending_ = tm.GetSignalQueuePending();
  for (auto const &sig : tm.GetPendingSignals()) {
    Enqueue(sig);
  }
}

// Unwind a sigframe from a Junction process's thread.
// Note Linux's rt_sigreturn expects the sigframe to be on the stack.
// Our rt_sigreturn assembly target switches stacks and calls this function with
// the old rsp as an argument.
extern "C" [[noreturn]] void usys_rt_sigreturn_finish(uint64_t rsp) {
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
  hand.ReplaceMask(sigframe->uc.mask);

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
std::optional<siginfo_t> ThreadSignalHandler::PopSigInfo(
    k_sigset_t blocked, bool reset_flag = true) {
  std::optional<siginfo_t> tmp;

  // Make sure sig_q_ lock is never acquired while holding shared_q lock
  rt::SpinGuard g(sig_q_);
  tmp = sig_q_.Pop(blocked);
  if (tmp) return tmp;

  {
    rt::SpinGuard g(shared_q_);
    tmp = shared_q_.Pop(blocked);
  }
  if (tmp) return tmp;

  if (reset_flag) {
    // No signal found, clear pending signal flags
    ResetInterruptState();

    // Restore syscall-stashed sigmask, if applicable
    if (RestoreBlockedNeeded()) RestoreBlockedLocked();
  }

  return tmp;
}

ThreadSignalHandler::ThreadSignalHandler(Thread &thread)
    : shared_q_(thread.get_process().get_signal_queue()), mythread_(thread){};

// Find next actionable signal
std::optional<DeliveredSignal> ThreadSignalHandler::GetNextSignal() {
  DeliveredSignal sig;

  while (true) {
    std::optional<siginfo_t> info = PopSigInfo(blocked_);
    if (!info) return std::nullopt;
    sig.info = *info;
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
  sig.prev_blocked = GetSigframeRestoreMask();
  ReplaceMask(to_block);

  if (unlikely(GetCfg().strace_enabled())) LogSignal(sig.info);

  return sig;
}

k_sigset_t ThreadSignalHandler::GetSigframeRestoreMask() {
  if (saved_blocked_) {
    k_sigset_t saved = *saved_blocked_;
    saved_blocked_ = std::nullopt;
    return saved;
  }
  return blocked_;
}

void ThreadSignalHandler::ResetInterruptState() {
  assert(sig_q_.IsHeld());
  notified_ = false;
  reset_interruptible_state(this_thread().GetCaladanThread());
}

void ThreadSignalHandler::ReplaceAndSaveBlocked(k_sigset_t mask) {
  assert(!RestoreBlockedNeeded());

  if (blocked_ == mask) return;
  saved_blocked_ = blocked_;
  ReplaceMask(mask);
}

void ThreadSignalHandler::RestoreBlocked() {
  assert(RestoreBlockedNeeded());

  // Avoid grabbing lock if interrupt flag is set
  if (thread_interrupted(this_thread().GetCaladanThread())) return;

  if (*saved_blocked_ != blocked_) {
    rt::SpinGuard g(sig_q_);
    if (thread_interrupted(this_thread().GetCaladanThread())) return;
    blocked_ = *saved_blocked_;
    SetInterruptFlagIfNeeded();
  }

  saved_blocked_ = std::nullopt;
}

bool ThreadSignalHandler::EnqueueSignal(const siginfo_t &info) {
  rt::SpinGuard g(sig_q_);

  // signal might already be pending
  if (!sig_q_.Enqueue(info)) return false;

  // signal is blocked, don't wakeup
  if (is_sig_blocked(info.si_signo)) return false;

  return TestAndSetNotify();
}

// Setup @signal on the stack given by @rsp (may be switched). @prev_frame is
// copied to the stack, and @new_frame is set to jump to the signal handler
void PushUserSigFrame(const DeliveredSignal &signal, uint64_t *rsp,
                      const thread_tf &prev_frame, thread_tf &new_frame) {
  // Fix RSP to ensure we are on the appropriate stack
  FixRspAltstack(signal, rsp);

  // Push siginfo
  *rsp -= sizeof(siginfo_t);
  siginfo_t *info = reinterpret_cast<siginfo_t *>(*rsp);
  *info = signal.info;

  // Push the restore frame to the stack
  thread_tf *restore_tf = PushTrapFrameToStack(rsp, prev_frame);

  // Use xsave's stack alignment even though we aren't using it here
  *rsp = AlignDown(*rsp, kXsaveAlignment);

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

// Try to drain pending signals. When done, jump to the last popped signal
// handler. Always called at the end of a syscall, does not return.
[[noreturn]] void ThreadSignalHandler::ApplySignalsAndExit(
    const DeliveredSignal &first_signal, uint64_t rsp,
    const thread_tf &restore_tf) {
  thread_tf sighand_tf;  // frame used to exit to signal handler

  PushUserSigFrame(first_signal, &rsp, restore_tf, sighand_tf);

  while (true) {
    std::optional<DeliveredSignal> d = GetNextSignal();
    if (d) {
      PushUserSigFrame(*d, &rsp, sighand_tf, sighand_tf);
      continue;
    }

    preempt_disable();
    mythread().set_in_syscall(false);
    if (!mythread().needs_interrupt()) {
      __switch_and_preempt_enable(&sighand_tf);
      std::unreachable();
    }

    // a signal slipped in, handle it and try again
    mythread().set_in_syscall(true);
    preempt_enable();
  }
}

extern "C" [[noreturn]] void ApplySignalsTrampoline(void *arg) {
  DeliveredSignal &d = *reinterpret_cast<DeliveredSignal *>(arg);

  thread_tf &ctx = mythread().get_fncall_regs();

  // assume that thread_tf is on the stack, use the space above. Leave redzone
  // empty just for extra safety, though shouldn't be needed.
  uint64_t rsp = reinterpret_cast<uintptr_t>(&ctx) - kRedzoneSize;
  rsp = AlignDown(rsp, 16) - 8;
  FixRspAltstack(d, &rsp);

  mythread().get_sighand().ApplySignalsAndExit(d, rsp, ctx);
}

// Prepare a trap frame that returns execution to rt_sigreturn to unwind a
// syscall signal
void SetupRestoreSignalEntry(uint64_t *rsp, int rax, thread_tf &tf) {
  assert(mythread().get_syscall_source() == SyscallEntry::kSyscallTrapSysStack);

  // move the frame to the bottom of the signal handler stack
  k_sigframe *frame =
      reinterpret_cast<k_sigframe *>(mythread().GetSyscallFrame());
  k_sigframe *new_frame = frame->CopyToStack(rsp);

  new_frame->uc.uc_mcontext.rax = rax;

  tf.rip = reinterpret_cast<uintptr_t>(syscall_rt_sigreturn);
  tf.rsp = reinterpret_cast<uintptr_t>(&new_frame->uc);
}

// Called by the Caladan scheduler to deliver signals to a thread that is being
// scheduled in and is not in a syscall (perhaps it was preempted).
// GetNextSignal() synchronizes with the signal handler lock, and is always
// called when returning to a thread that was not in a syscall.
extern "C" void deliver_signals_jmp_thread(thread_t *th) {
  assert(sched_needs_signal_check(th));
  assert_preempt_disabled();
  assert_on_runtime_stack();

  ThreadSignalHandler &hand = Thread::fromCaladanThread(th).get_sighand();

  thread_tf &tf = thread_self()->tf;

  uint64_t rsp = tf.rsp;

  while (true) {
    std::optional<DeliveredSignal> d = hand.GetNextSignal();
    if (!d) break;

    PushUserSigFrame(*d, &rsp, tf, tf);
  }
}

[[nodiscard]] bool WantsRestartSysNoHandler(int rax) {
  return rax == -ERESTARTNOHAND || rax == -ERESTARTSYS;
}

// Check if restart is needed post handler. May mutate @rax.
[[nodiscard]] bool WantsRestartSysPostHandler(int &rax,
                                              const DeliveredSignal &sig) {
  if (rax == -ERESTARTNOHAND) {
    rax = -EINTR;
    return false;
  }

  if (rax == -ERESTARTSYS) {
    if (sig.act.is_restartsys()) return true;
    rax = -EINTR;
    return false;
  }

  return false;
}

uint64_t RewindIndirectSystemCall(uint64_t rip) {
  // rewind seven bytes: ff 14 25 28 0e 20 00    call   *0x200e28
  return rip - 7;
}

// Restart a syscall by returning to the entry of a usys_* function with the
// same registers and stack data.
[[noreturn]] void RestartSyscall() {
  thread_tf tf;

  Thread &myth = mythread();

  SyscallEntry type = myth.get_syscall_source();

  if (type == SyscallEntry::kSyscallTrapSysStack) {
    const sigcontext &ctx = myth.get_trap_regs();

    // can ignore caller-saved registers for the trap entry path
    tf.rax = ctx.trapno;
    tf.rsp = reinterpret_cast<uint64_t>(myth.GetSyscallFrame());
    tf.rdi = ctx.rdi;
    tf.rsi = ctx.rsi;
    tf.rdx = ctx.rdx;
    tf.r8 = ctx.r8;
    tf.r9 = ctx.r9;
    tf.rcx = ctx.r10;
    assert(tf.rax < SYS_NR);
    tf.rip = reinterpret_cast<uint64_t>(sys_tbl[tf.rax]);
  } else {
    // copy all registers from syscall entry
    tf = myth.get_fncall_regs();

    // reset RAX
    tf.rax = tf.orig_rax;

    tf.rip = RewindIndirectSystemCall(tf.rip);
  }

  __jmp_syscall_restart_nosave(&tf);
}

void ThreadSignalHandler::RunPending(int rax) {
  std::optional<DeliveredSignal> sig = GetNextSignal();
  if (!sig) {
    if (WantsRestartSysNoHandler(rax)) RestartSyscall();
    return;
  }

  // we don't support re-entrant syscalls on the syscall stack, so we can't
  // leave state on this stack when running signals. Instead, arrange for the
  // signal return to bring execution back to the system call entry point,
  // either with a return value in rax or to repeat the system call.

  bool do_restart = WantsRestartSysPostHandler(rax, *sig);
  SyscallEntry entry = mythread().get_syscall_source();

  if (entry == SyscallEntry::kSyscallTrapSysStack) {
    sigcontext &ctx = mythread().get_trap_regs();
    uint64_t rsp = ctx.rsp;
    FixRspAltstack(*sig, &rsp);

    if (do_restart) {
      ctx.rip -= 2;
      ctx.rax = ctx.trapno;
    } else {
      ctx.rax = rax;
    }

    thread_tf tmp;
    SetupRestoreSignalEntry(&rsp, rax, tmp);
    ApplySignalsAndExit(*sig, rsp, tmp);
  }

  thread_tf &ctx = mythread().get_fncall_regs();
  if (do_restart) {
    ctx.rip = RewindIndirectSystemCall(ctx.rip);
    ctx.rax = ctx.orig_rax;
  } else {
    ctx.rax = rax;
  }

  if (entry == SyscallEntry::kFunctionCallUserStack) {
    // Need to switch stacks to proceed.

    // copy signal to new stack
    uint64_t new_rsp = GetSyscallStackBottom();
    new_rsp -= sizeof(DeliveredSignal);
    DeliveredSignal *d = reinterpret_cast<DeliveredSignal *>(new_rsp);
    *d = *sig;

    new_rsp = AlignDown(new_rsp, 16) - 8;

    __nosave_switch(ApplySignalsTrampoline, new_rsp,
                    reinterpret_cast<uint64_t>(d));
  } else {
    assert(entry == SyscallEntry::kFunctionCallSysStack);
    uint64_t rsp = mythread().get_fncall_regs().rsp;
    FixRspAltstack(*sig, &rsp);
    ApplySignalsAndExit(*sig, rsp, mythread().get_fncall_regs());
  }
}

long usys_rt_sigaction(int sig, const struct k_sigaction *iact,
                       struct k_sigaction *oact, size_t sigsetsize) {
  if (unlikely(sigsetsize != sizeof(k_sigset_t))) return -EINVAL;
  if (unlikely(SignalInMask(kSignalKernelOnlyMask, sig))) return -EINVAL;
  k_sigaction sa;
  if (iact)
    sa = myproc().get_signal_table().exchange_action(sig, *iact);
  else
    sa = myproc().get_signal_table().get_action(sig);
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
  Status<void> ret = myproc().SignalThread(tid, *info);
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

  unsigned long oset, mask = *reinterpret_cast<const k_sigset_t *>(set);
  hand.SigProcMask(SIG_UNBLOCK, &mask, &oset);

  std::optional<Duration> timeout;
  if (ts) timeout = Duration(*ts);

  bool again = true;

  if (!hand.any_sig_ready() && (!timeout || !timeout->IsZero())) {
    rt::ThreadWaker w;
    rt::Spin lock;
    rt::WakeOnTimeout timed_out(lock, w, timeout);
    rt::SpinGuard g(lock);
    rt::WaitInterruptible(lock, w, [&timed_out] { return !!timed_out; });
    again = !!timed_out;
  }

  std::optional<siginfo_t> tmp = hand.PopSigInfo(~mask);
  hand.ReplaceMask(oset);
  if (!tmp) return again ? -EAGAIN : -EINTR;

  *info = *tmp;
  return tmp->si_signo;
}

int usys_rt_sigsuspend(const sigset_t *set, size_t sigsetsize) {
  if (unlikely(sigsetsize != sizeof(k_sigset_t))) return -EINVAL;

  const k_sigset_t *mask = reinterpret_cast<const k_sigset_t *>(set);

  ThreadSignalHandler &hand = mythread().get_sighand();
  hand.ReplaceAndSaveBlocked(*mask);

  {
    rt::Preempt p;
    rt::ThreadWaker w;
    rt::PreemptGuard g(p);
    rt::WaitInterruptible(p, w);
  }

  return -ERESTARTNOHAND;
}

long usys_pause() {
  thread_t *th = thread_self();
  if (unlikely(rt::SetInterruptible(th))) return -ERESTARTNOHAND;
  rt::Preempt p;
  p.Lock();
  p.UnlockAndPark();
  return -ERESTARTNOHAND;
}

extern "C" void RunSignals(int rax) {
  mythread().get_sighand().RunPending(rax);
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

void SignalTable::Snapshot(ProcessMetadata &s) const & {
  for (size_t idx = 0; idx < kNumSignals; idx++) {
    s.AddSignalTableEntry(idx, table_[idx]);
  }
}

void SignalTable::Restore(ProcessMetadata const &pm) {
  auto signals = pm.GetSignalTable();
  for (int i = 0; i < kNumSignals; i++) {
    table_[i] = signals[i];
  }
}

}  // namespace junction
