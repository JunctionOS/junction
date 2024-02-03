
extern "C" {
#include <alloca.h>
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
#include "junction/bindings/stack.h"
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
extern "C" void SigKillHandler(int signo, siginfo_t *info, void *c) {
  junction_fncall_enter(128 + signo, 0, 0, 0, 0, 0, __NR_exit_group);
  std::unreachable();
}

static const k_sigaction SigKillAction = {
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

// Interrupt handlers don't run in syscall context (they run with
// preemption/interrupts disabled). If a SIGSTOP is delivered, we switch to a
// syscall context (with the return trapframe set to the interrupt trapframe) so
// we can do an interruptible wait for a future SIGCONT. This same mechanism is
// used for signal delivery from the runtime scheduler context.
void ForceIntoSyscall(Thread &myth, const Trapframe &cur_frame,
                      thread_tf &jmp_tf) {
  assert(myth.GetCaladanThread() == thread_self());
  assert(!myth.in_kernel());
  const stack &syscall_stack = *myth.GetCaladanThread()->stack;

  // If an interrupts was delivered on top of the syscall stack, earlier code
  // should have detected this and restored to the syscall exit handler.
  assert(!IsOnStack(cur_frame.GetRsp(), syscall_stack));

  // Copy the interrupt frame to the syscall stack
  uint64_t rsp = GetSyscallStackBottom();
  Trapframe &stack_frame = cur_frame.CloneTo(&rsp);

  // Mark entering the kernel and record the location of the exit frame.
  myth.mark_enter_kernel();
  myth.SetTrapframe(stack_frame);

  // Provide the caller with a tf that will jump to the syscall exit handler.
  stack_frame.MakeUnwinderSysret(jmp_tf);
}

// An interrupt was delivered while a Junction thread was running. This function
// moves the trapframe to the Junction thread's syscall stack so it can be
// restored in the future.
void MoveSigframeToJunctionThread(const KernelSignalTf &sigframe,
                                  thread_tf &tf) {
  assert(IsJunctionThread());
  Thread &myth = mythread();
  stack &syscall_stack = *myth.GetCaladanThread()->stack;

  uint64_t rsp = sigframe.GetRsp() - kRedzoneSize;
  bool on_syscall_stack = IsOnStack(rsp, syscall_stack);
  bool in_kernel = myth.in_kernel();

  // There is a race that may occur when a stack-switching system call is
  // returning: it may clear the in_syscall flag before leaving the stack.
  // In this case, the trapframe that was saved at syscall entry (and updated
  // before returning) will be our target restore trapframe instead of the
  // provided sigframe.
  if (unlikely(!in_kernel && on_syscall_stack)) {
    myth.mark_enter_kernel();
    myth.GetSyscallFrame().MakeUnwinderSysret(tf);
    assert(IsOnStack(tf.rsp, syscall_stack));
    return;
  }

  // We are going to unwind this sigframe by moving it to the syscall stack
  // and then re-enabling preemption. Because the syscall stack does not support
  // re-entrant system calls, care must be taken to ensure that user-level
  // signal delivery does not occur on this stack. Normally this is handled by
  // setting the in_syscall flag while using the stack. If the thread is not
  // currently "in_syscall", mark it as such to prevent future signal handlers
  // from running on the syscall stack.

  if (!on_syscall_stack) rsp = GetSyscallStackBottom(syscall_stack);

  // copy the sigframe over
  KernelSignalTf &stack_frame = sigframe.CloneTo(&rsp);

  if (!in_kernel) {
    myth.mark_enter_kernel();
    myth.SetTrapframe(stack_frame);
    stack_frame.MakeUnwinderSysret(tf);
  } else {
    stack_frame.MakeUnwinder(tf);
  }
}

// Setup @signal on the stack given by @rsp (may be switched). @prev_frame is
// copied to the stack, and @new_frame is set to jump to the signal handler
void PushUserSigFrame(const DeliveredSignal &signal, uint64_t *rsp,
                      const Trapframe &prev_frame, thread_tf &new_frame) {
  // Fix RSP to ensure we are on the appropriate stack.
  *rsp = signal.FixRspAltstack(*rsp);

  // Push siginfo.
  siginfo_t *info = PushToStack(rsp, signal.info);

  // Push the previous frame.
  prev_frame.CloneSigframe(rsp);

  // Push a fake kernel sigframe.
  k_sigframe *kframe = AllocateOnStack<k_sigframe>(rsp);
  kframe->pretcode = reinterpret_cast<char *>(signal.act.restorer);
  kframe->uc.uc_flags = 0;
  kframe->uc.uc_link = 0;
  kframe->uc.uc_stack = signal.ss;
  kframe->uc.mask = signal.prev_blocked;
  kframe->uc.uc_mcontext.fpstate = nullptr;

  assert(*rsp % 16 == 8);

  // Prepare a trapframe to jump to this signal handler/stack
  new_frame.rsp = reinterpret_cast<uint64_t>(kframe);
  new_frame.rip = reinterpret_cast<uint64_t>(signal.act.handler);
  new_frame.rdi = static_cast<uint64_t>(signal.info.si_signo);
  new_frame.rsi = reinterpret_cast<uint64_t>(info);
  new_frame.rdx = reinterpret_cast<uint64_t>(&kframe->uc);
}

inline void PushUserSigFrame(const DeliveredSignal &signal, uint64_t *rsp,
                             thread_tf &frame) {
  PushUserSigFrame(signal, rsp, FunctionCallTf(&frame), frame);
}

// Handle a kick delivered by host OS signal or UIPI.
// If signals are delivered to a user thread, HandleKick does not return.
template <typename Frame>
__always_inline void HandleKick(const Frame &sigframe)
  requires InterruptFrame<Frame>
{
  assert(IsJunctionThread());

  Thread &th = mythread();

  // Signal delivery will happen when the syscall returns.
  if (th.in_kernel()) return;

  uint64_t rsp = sigframe.GetRsp() - kRedzoneSize;

  // Deal with potential race for stack-switching system calls that clear the
  // in_kernel flag before switching back to the caller stack. In this case,
  // the caller of HandleKick must detect this and rewind the return code
  // to-recheck for signals.
  if constexpr (Frame::HasStackSwitchRace())
    if (unlikely(IsOnStack(rsp, GetSyscallStack()))) return;

  bool stop = false;
  thread_tf restore_tf;

  ThreadSignalHandler &hand = th.get_sighand();
  std::optional<DeliveredSignal> sig = hand.GetNextSignal(&stop);
  if (!sig) {
    if (stop) {
      ForceIntoSyscall(th, sigframe, restore_tf);
      Frame::SwitchFromInterruptContext(restore_tf);
      std::unreachable();
    }
    return;
  }

  // Push the first signal to the stack.
  PushUserSigFrame(*sig, &rsp, sigframe, restore_tf);

  // Add subsequent signals.
  while (true) {
    sig = hand.GetNextSignal(&stop);
    if (!sig) break;
    PushUserSigFrame(*sig, &rsp, restore_tf);
  }

  if (stop) ForceIntoSyscall(th, FunctionCallTf(restore_tf), restore_tf);

  Frame::SwitchFromInterruptContext(restore_tf);
}

// Place UINTR handler logic that follows an xsave here so compiler can
// inline/use floating point.
void UintrFinishYield(u_sigframe *uintr_frame, thread_t *th, void *xsave_buf,
                      uint64_t rsp) {
  UintrTf &stack_frame = UintrTf(uintr_frame).CloneTo(&rsp);
  stack_frame.GetFrame().AttachXstate(xsave_buf);

  // Set up the proper unwinder.
  if (!th->junction_thread || th->in_syscall) {
    stack_frame.MakeUnwinder(th->tf);
  } else {
    Thread &myth = mythread();
    myth.mark_enter_kernel();
    myth.SetTrapframe(stack_frame);
    stack_frame.MakeUnwinderSysret(th->tf);
  }

  preempt_disable();
  SetFSBase(perthread_read(runtime_fsbase));
  void *stack = perthread_read(runtime_stack);

  // switch to the runtime stack and re-enable user interrupts
  if (preempt_cede_needed(myk()))
    nosave_switch_setui(thread_finish_cede, stack);
  else
    nosave_switch_setui(thread_finish_yield, stack);

  std::unreachable();
}

void HandleKickUintrFinish(u_sigframe *uintr_frame, void *xsave_buf) {
  uintr_frame->AttachXstate(xsave_buf);
  HandleKick(UintrTf(uintr_frame));
}

extern "C" __nofp void uintr_entry(u_sigframe *uintr_frame) {
  void *xsave_buf;

  STAT(PREEMPTIONS)++;

  // resume execution if preemption is disabled.
  if (!preempt_enabled()) {
    perthread_andi(preempt_cnt, 0x7fffffff);
    return;
  }

  // Take care here to avoid calling functions not marked as __nofp. (The
  // compiler will allow you to do this without complaining.)

  thread_t *th = perthread_read(__self);

  // try to use the per-uthread xsave area. when signals are stacked this may
  // not be possible.
  if (!th->xsave_area_in_use) {
    // xsaveopt uses the modified optimization to avoid saving states that have
    // not been modified since the last restore from this buffer. Hardware
    // limitations prevent it from distinguishing between xrstors in different
    // applications that use the same virtual address for the buffer. To check
    // that the last executed xrstor was performed with this buffer by this
    // application, we track per-core (using perthread) the last buffer used for
    // xrstor. When a kthread parks, this field is cleared. We assume that
    // non-Junction processes (system services, etc.) which may share this core
    // do not use xrstor. If they do, we will need to run Junction on isolated
    // cores in order to make this correct.

    xsave_buf = GetXsaveAreaNoFp(*th->stack);
    if (th->xsave_area_active && xsave_buf == perthread_read(last_xrstor_buf)) {
      // Use the modified optimization when xrstor was last used with this buf
      XSaveOpt(xsave_buf, xsave_features);
    } else {
      // Use the full xsave (more expensive than the compact version) in the
      // hope that we can use xsaveopt next time.
      XSave(xsave_buf, xsave_features);
    }
    th->xsave_area_in_use = true;
    th->xsave_area_active = true;
  } else {
    xsave_buf = nullptr;
  }

  if (th->junction_thread && uintr_frame->uirrv == SIGURG - 1) {
    if (!xsave_buf) {
      // Temporarily save xstate on the UINTR stack. HandleKick will copy it if
      // a signal is delivered.
      uint64_t this_rsp = reinterpret_cast<uint64_t>(
          alloca(xsave_max_size + kXsaveAlignment - 1));
      // AlignUp
      this_rsp = (this_rsp + kXsaveAlignment - 1) & ~(kXsaveAlignment - 1);
      xsave_buf = reinterpret_cast<void *>(this_rsp);
      XSaveCompact(xsave_buf, xsave_features);
    }

    // Use a function that is not marked nofp to perform the remaining
    // operations.
    HandleKickUintrFinish(uintr_frame, xsave_buf);

    // If we return to this point, restore the floating point state.
    uintr_frame->RestoreXstate();
    return;
  }

  uint64_t rsp = uintr_frame->rsp - kRedzoneSize;

  if (!xsave_buf) {
    // We need to determine where we should place xstate before saving it.
    // If this interrupt landed on a non-Junction thread, place the xstate
    // directly on the interrupted stack. If this interrupt landed on a Junction
    // thread, place the xstate onto the syscall stack.
    if (th->junction_thread && !IsOnStackNoFp(rsp, *th->stack))
      rsp = GetSyscallStackBottomNoFp(*th->stack);

    // AlignDown
    rsp = (rsp - xsave_max_size) & ~(kXsaveAlignment - 1);
    xsave_buf = reinterpret_cast<void *>(rsp);

    // Safe to use fp functions after calling XSave.
    XSaveCompact(xsave_buf, xsave_features);
  }

  UintrFinishYield(uintr_frame, th, xsave_buf, rsp);

  __builtin_unreachable();
}

// Signal handler for IOKernel sent signals (SIGUSR1 + SIGUSR2)
// Also handles SIGURG to deliver pending signals
extern "C" void caladan_signal_handler(int signo, siginfo_t *info,
                                       void *context) {
  STAT(PREEMPTIONS)++;

  assert(!uintr_enabled);

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

  KernelSignalTf sigframe(uc);
  sigframe.GetFrame().InvalidateAltStack();

  if (IsJunctionThread()) {
    if (signo == SIGURG) {
      // Try to setup signals.
      HandleKick(sigframe);

      // If we return to this point there is no signal to deliver, move to a
      // preemption-safe stack, reenable preemption, and then do an
      // rt_sigreturn.
      thread_tf restore_tf;
      MoveSigframeToJunctionThread(sigframe, restore_tf);
      __switch_and_preempt_enable(&restore_tf);
      std::unreachable();
    }

    MoveSigframeToJunctionThread(sigframe, thread_self()->tf);
  } else {
    uint64_t rsp = sigframe.GetRsp() - kRedzoneSize;
    sigframe.CloneTo(&rsp).MakeUnwinder(thread_self()->tf);
  }

  // restore runtime FS register
  SetFSBase(perthread_read(runtime_fsbase));

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
    case SignalAction::kStop:
      // TODO(jfried) remove these signal actions?
      return std::nullopt;
    case SignalAction::kTerminate:
    case SignalAction::kCoredump:
      return SigKillAction;
  }

  std::unreachable();
}

[[noreturn]] void ThreadSignalHandler::DeliverKernelSigToUser(
    int signo, siginfo_t *info, const KernelSignalTf &sigframe) {
  assert_on_runtime_stack();

  std::optional<k_sigaction> tmp;
  if (likely(!is_sig_blocked(signo)))
    tmp = GetAction(signo);
  else
    LOG(WARN) << "synchronous signal blocked";

  // synchronous signal kills program if no action is specified
  const k_sigaction &act = tmp ? *tmp : SigKillAction;

  // Determine stack to use
  uint64_t rsp = sigframe.GetRsp() - kRedzoneSize;
  const stack_t &ss = get_altstack();
  if (act.wants_altstack() && has_altstack() && !IsOnStack(rsp, ss))
    rsp = reinterpret_cast<uint64_t>(ss.ss_sp) + ss.ss_size;

  // transfer the frame
  k_sigframe *new_frame = sigframe.PushUserVisibleFrame(&rsp);

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
  if (saved_blocked_) s.SetSignalHandlerSavedBlocked(*saved_blocked_);
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

  if (unlikely(!thread_self()))
    print_msg_abort("Unexpected signal delivered to Caladan code");

  if (unlikely(!IsJunctionThread()))
    print_msg_abort("Unexpected signal delivered to Junction code");

  if (unlikely(!preempt_enabled()))
    print_msg_abort("signal delivered while preemption is disabled");

  if (unlikely(mythread().in_kernel()))
    print_msg_abort("signal delivered while in Junction syscall handler");

  if (unlikely(!context)) print_msg_abort("signal delivered without context");

  preempt_disable();
  assert_on_runtime_stack();

  mythread().get_sighand().DeliverKernelSigToUser(signo, info,
                                                  KernelSignalTf(uc));
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

    // Is this the first instance of this signal that we've found?
    if (!si.si_signo) {
      if (!remove) return *p;
      si = *p;
      p = pending_q_.erase(p);
      // Legacy signals are only enqueued once, end the search here.
      if (si.si_signo < kNumStandardSignals) break;
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

  assert(!SignalInMask(kStopStartSignals, signo));

  if (signo < kNumStandardSignals) {
    if (is_sig_pending(signo)) return false;
  } else {
    if (unlikely(pending_q_.size() >= kMaxQueuedRT)) {
      LOG_ONCE(ERR) << "Dropping RT signals";
      return false;
    }
  }

  pending_q_.emplace_back(info);
  set_sig_pending(signo);
  return true;
}

void SignalQueue::Snapshot(ProcessMetadata &snapshot) const & {
  snapshot.SetSignalQueuePending(pending_);
  snapshot.ReserveNPendingSignals(pending_q_.size());
  for (auto sig : pending_q_) snapshot.AddPendingSignal(sig);
}

void SignalQueue::Snapshot(ThreadMetadata &snapshot) const & {
  snapshot.SetSignalQueuePending(pending_);
  snapshot.ReserveNPendingSignals(pending_q_.size());
  for (auto sig : pending_q_) snapshot.AddPendingSignal(sig);
}

void SignalQueue::Restore(ProcessMetadata const &pm) {
  pending_ = pm.GetSignalQueuePending();
  for (auto const &sig : pm.GetPendingSignals()) Enqueue(sig);
}

void SignalQueue::Restore(ThreadMetadata const &tm) {
  pending_ = tm.GetSignalQueuePending();
  for (auto const &sig : tm.GetPendingSignals()) Enqueue(sig);
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

  // Unwind.
  jframe->Unwind();
  std::unreachable();
}

// Find next signal pending in either the thread or proc siqueues.
std::optional<siginfo_t> ThreadSignalHandler::PopSigInfo(k_sigset_t blocked,
                                                         bool reset_flag = true,
                                                         bool *stop = nullptr) {
  std::optional<siginfo_t> tmp;

  // Make sure sig_q_ lock is never acquired while holding shared_q lock
  rt::SpinGuard g(sig_q_);
  tmp = sig_q_.Pop(blocked);
  if (tmp) return tmp;

  {
    rt::SpinGuard g(shared_q_);

    // Check for SIGSTOP
    if (stop && this_thread().get_process().is_stopped()) {
      *stop = true;
      return std::nullopt;
    }

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
std::optional<DeliveredSignal> ThreadSignalHandler::GetNextSignal(bool *stop) {
  DeliveredSignal sig;

  assert(stop != nullptr);

  while (true) {
    std::optional<siginfo_t> info = PopSigInfo(blocked_, true, stop);
    if (!info) return std::nullopt;
    std::optional<k_sigaction> act = GetAction(info->si_signo);

    // try again if signal is ignored
    if (!act) continue;

    sig.info = *info;
    sig.act = *act;
    break;
  }

  // Record the altstack, disable if needed
  sig.ss = get_altstack();
  if (sig.ss.ss_flags & kSigStackAutoDisarm) DisableAltStack();

  // Apply blocked signal mask
  unsigned long to_block = sig.act.sa_mask;
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

// Called by the Caladan scheduler to deliver signals to a thread that is being
// scheduled in and is not in a syscall (perhaps it was preempted).
// GetNextSignal() synchronizes with the signal handler lock, and is always
// called when returning to a thread that was not in a syscall.
extern "C" void deliver_signals_jmp_thread(thread_t *th) {
  assert(sched_needs_signal_check(th));
  assert_preempt_disabled();
  assert_on_runtime_stack();

  Thread &myth = Thread::fromCaladanThread(th);
  thread_tf &tf = th->tf;
  uint64_t rsp = tf.rsp;

  assert(!myth.in_kernel());

  if (IsOnStack(rsp, GetSyscallStack(th))) {
    myth.mark_enter_kernel();
    myth.GetSyscallFrame().MakeUnwinderSysret(tf);
    return;
  }

  ThreadSignalHandler &hand = myth.get_sighand();

  while (true) {
    bool stop = false;
    std::optional<DeliveredSignal> d = hand.GetNextSignal(&stop);
    if (d) {
      PushUserSigFrame(*d, &rsp, tf);
      continue;
    }

    if (stop) ForceIntoSyscall(myth, FunctionCallTf(tf), tf);
    break;
  }
}

[[nodiscard]] bool IsRestartSys(int rax) {
  return rax == -ERESTARTNOHAND || rax == -ERESTARTSYS;
}

// Check if restart is needed post handler, updates the trapframe if needed.
void CheckRestartSysPostHandler(SyscallFrame &entry, int rax,
                                const DeliveredSignal &sig) {
  assert(IsRestartSys(rax));
  if (rax == -ERESTARTNOHAND) {
    entry.SetRax(-EINTR);
  } else {
    if (sig.act.is_restartsys()) {
      entry.ResetToSyscallStart();
    } else {
      entry.SetRax(-EINTR);
    }
  }
}

// rax is non-zero only if returning from a system call.
void ThreadSignalHandler::DeliverSignals(const Trapframe &entry, int rax) {
  bool stop = false;
  std::optional<DeliveredSignal> sig = GetNextSignal(&stop);
  if (!sig) {
    bool wants_restart = IsRestartSys(rax);
    if (stop) {
      // Don't restart after stopping.
      if (wants_restart) this_thread().GetSyscallFrame().SetRax(-EINTR);
      myproc().ThreadStopWait();
      // The interrupt flag is not cleared; this function will immediately run
      // again.
      return;
    }
    if (!wants_restart) return;
    this_thread().GetSyscallFrame().JmpRestartSyscall();
    std::unreachable();
  }

  if (IsRestartSys(rax))
    CheckRestartSysPostHandler(this_thread().GetSyscallFrame(), rax, *sig);

  RunOnSyscallStack([this, d = *sig, entry = &entry]() mutable {
    // HACK: entry might be sitting on top of this RSP, will need a better a
    // solution, but for now just try to avoid the area immediately above RSP.
    uint64_t rsp =
        entry->GetRsp() - std::max(kRedzoneSize, 2 * sizeof(thread_tf));

    thread_tf sighand_tf;

    PushUserSigFrame(d, &rsp, *entry, sighand_tf);

    Thread &myth = mythread();

    bool stop = false;

    while (true) {
      std::optional<DeliveredSignal> d = GetNextSignal(&stop);
      if (d) {
        PushUserSigFrame(*d, &rsp, sighand_tf);
        continue;
      } else if (stop) {
        FunctionCallTf temp_tf(sighand_tf);
        myth.SetTrapframe(temp_tf);
        myth.get_process().ThreadStopWait();
        continue;
      }

      preempt_disable();
      myth.mark_leave_kernel();
      if (!myth.needs_interrupt()) {
        __switch_and_preempt_enable(&sighand_tf);
        std::unreachable();
      }

      // a signal slipped in, handle it and try again
      myth.mark_enter_kernel();
      preempt_enable();
    }
  });
};

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

long usys_kill(pid_t tgid, int sig) {
  if (tgid == myproc().get_pid()) {
    myproc().Signal(sig);
    return 0;
  } else {
    std::shared_ptr<Process> proc = Process::Find(tgid);
    if (!proc) return -ESRCH;
    proc->Signal(sig);
    return 0;
  }
}

long usys_tgkill(pid_t tgid, pid_t tid, int sig) {
  Status<void> ret;

  if (tgid == myproc().get_pid()) {
    ret = myproc().SignalThread(tid, sig);
  } else {
    std::shared_ptr<Process> proc = Process::Find(tgid);
    if (!proc) return -ESRCH;
    ret = proc->SignalThread(tid, sig);
  }

  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

long usys_rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *info) {
  info->si_signo = sig;

  Status<void> ret;
  if (tgid == myproc().get_pid()) {
    ret = myproc().SignalThread(tid, *info);
  } else {
    std::shared_ptr<Process> proc = Process::Find(tgid);
    if (!proc) return -ESRCH;
    ret = proc->SignalThread(tid, sig);
  }

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
  Thread &th = mythread();
  th.get_sighand().DeliverSignals(th.GetTrapframe(), rax);
}

Status<void> InitSignal() {
  if (uintr_enabled && xsave_max_size > XSAVE_AREA_SIZE) {
    LOG(ERR) << "ERROR: this machine requires " << xsave_max_size
             << " bytes for XSAVE area, but only " << XSAVE_AREA_SIZE
             << " bytes were reserved. "
             << "Please recompile with a larger XSAVE_AREA_RESERVED.";
    return MakeError(-1);
  }

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
  for (size_t idx = 0; idx < kNumSignals; idx++)
    s.AddSignalTableEntry(idx, table_[idx]);
}

void SignalTable::Restore(ProcessMetadata const &pm) {
  auto signals = pm.GetSignalTable();
  for (int i = 0; i < kNumSignals; i++) table_[i] = signals[i];
}

}  // namespace junction
