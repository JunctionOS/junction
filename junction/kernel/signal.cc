
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
  kStop,  // pause the thread on delivery
  // kContinue,   // continue the thread if stopped
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
  // SIGCONT is handled specially elsewhere.
  if (SignalInMask(kSignalStopMask, sig)) return SignalAction::kStop;
  if (SignalInMask(kSignalCoredumpMask, sig)) return SignalAction::kCoredump;
  if (SignalInMask(kSignalIgnoreMask, sig)) return SignalAction::kIgnore;
  return SignalAction::kTerminate;
}

// ref:
// https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/trap_pf.h
constexpr int kPfInstruction = 1 << 4;
constexpr int kPfWrite = 1 << 1;

// When a SIGSEGV occurs, the type of access (read/write/execute)
// is stored inside the sigcontext at `uc_mcontext`.
//
// This function translates that information into the required
// protection for the VMA to have, which is needed by the tracer fault handler
int sigsegv_sigcontext_to_prot(const struct sigcontext &context) {
  if ((context.err & kPfWrite) != 0) {
    return PROT_WRITE;
  } else if ((context.err & kPfInstruction) != 0) {
    return PROT_EXEC;
  }
  return PROT_READ;
}

// A signal handler that can be injected into a program to cleanly kill it
extern "C" void SigKillHandler(int signo, siginfo_t *info, void *c) {
  assert_stack_is_aligned();
  junction_fncall_enter(128 + signo, 0, 0, 0, 0, 0, __NR_exit_group);
  std::unreachable();
}

static const k_sigaction SigKillAction = {
    .handler = SigKillHandler,
    .sa_flags = SA_ONSTACK | SA_RESTART | SA_NODEFER,
    .sa_mask = ~0UL,  // all signals masked
};

static size_t __strlen(const char *msg) {
  size_t len;
  for (len = 0; *msg; msg++, len++)
    ;
  return len;
}

void __noinline write_uint(const char *msg, uint64_t num) {
  char buf[32];
  char *pos = &buf[32];
  do {
    pos--;
    *pos = '0' + num % 10;
    num /= 10;
  } while (num > 0);
  syscall_write(2, msg, __strlen(msg));
  syscall_write(2, pos, &buf[32] - pos);
  syscall_write(2, "\n", 1);
}

void __noinline print_msg_abort(const char *msg) {
  const char *m = "Aborting on signal: ";
  syscall_write(2, m, __strlen(m));
  syscall_write(2, msg, __strlen(msg));
  syscall_write(2, "\n", 1);
  syscall_exit(-1);
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

// Apply as many signals as are available to for myth. The previous trapframe is
// given at @frame, and if any signals are applied, the restore_tf will contain
// a trapframe to jump to the handler.
[[nodiscard]] bool ApplyAllSignals(Thread &myth, uint64_t *rsp,
                                   Trapframe &frame, thread_tf &restore_tf) {
  ThreadSignalHandler &hand = myth.get_sighand();

  const Trapframe *prev = &frame;
  FunctionCallTf restore_wrapper(restore_tf);
  size_t sig_count = 0;
  while (true) {
    std::optional<DeliveredSignal> sig = hand.GetNextSignal();
    if (!sig) break;

    if (!sig_count) myth.get_rseq().fixup(myth, &frame);

    PushUserSigFrame(*sig, rsp, *prev, restore_tf);
    prev = &restore_wrapper;
    sig_count++;
  }

  return sig_count > 0;
}

// Determine what was interrupted...
FaultStatus GetFaultStatus(Thread &th, uint64_t fault_sp, uint64_t fault_ip) {
  if (th.in_kernel()) return FaultStatus::kInSyscall;
  if (unlikely(th.rsp_on_syscall_stack(fault_sp)))
    return FaultStatus::kCompletingSyscall;
  // If we are not going to snapshot, the previous checks are sufficient to
  // determine fault status. If we are going to snapshot, we have to also make
  // sure that we don't snapshot any signal frames that point to Junction code.
  // This can happen when our snapshot stop signal interrupts a system call just
  // as it is starting or completing (just before/after it sets/clears the
  // in_kernel flag).
  if (unlikely(GetCfg().expecting_snapshot())) return CheckFaultIP(fault_ip);
  return FaultStatus::kNotInSyscall;
}

// Place UINTR handler logic that follows an xsave here so compiler can
// inline/use floating point.
void UintrFinishYield(u_sigframe *uintr_frame, thread_t *th, void *xsave_buf,
                      uint64_t rsp, bool was_xsave_area_used) {
  assert_on_uintr_stack();

  UintrTf &stack_frame = UintrTf(uintr_frame).CloneTo(&rsp);
  // Attach xsave_buf (located on rsp or in xsave_area) after cloning the
  // uintr_frame to avoid a copy.
  stack_frame.GetFrame().AttachXstate(xsave_buf);

  // Set up the proper unwinder.
  if (!th->junction_thread) {
    stack_frame.MakeUnwinder(th->tf);
  } else {
    Thread &myth = mythread();

    // Do a more thorough check to ensure that we are not in/exiting a syscall.
    FaultStatus fstatus =
        GetFaultStatus(myth, uintr_frame->GetRsp(), uintr_frame->GetRip());

    if (fstatus == FaultStatus::kInSyscall) {
      // Just undo this trapframe and resume the system call at next sched.
      stack_frame.MakeUnwinder(th->tf);
    } else if (fstatus == FaultStatus::kNotInSyscall) {
      // Unwind this frame and check for pending signals at next sched.
      myth.mark_enter_kernel();
      stack_frame.MakeUnwinderSysret(myth, th->tf);
    } else if (unlikely(fstatus == FaultStatus::kCompletingSyscall)) {
      // Rare case where we got caught right as a syscall exited, restart the
      // syscall exit process.
      myth.mark_enter_kernel();
      myth.GetTrapframe().MakeUnwinderSysret(myth, th->tf);
      th->xsave_area_in_use =
          was_xsave_area_used;  // we are abandoning the saved trapframe.
    }
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

void HandleKickUintrFinish(thread_t *th, u_sigframe *uintr_frame,
                           void *xsave_buf, bool prev_xsave_area_used) {
  assert_on_uintr_stack();

  Thread &myth = Thread::fromCaladanThread(th);

  // Do a more thorough check to ensure that we are not in/exiting a syscall.
  FaultStatus fstatus =
      GetFaultStatus(myth, uintr_frame->GetRsp(), uintr_frame->GetRip());
  if (unlikely(fstatus != FaultStatus::kNotInSyscall)) {
    // We did an earlier check for FaultStatus::kInSyscall
    assert(fstatus == FaultStatus::kCompletingSyscall);

    // We are totally abandoning the captured xsave state, this frees it if was
    // using the thread-private xsave area.
    th->xsave_area_in_use = prev_xsave_area_used;

    // Restart the system call exit process.
    thread_tf out_tf;
    myth.mark_enter_kernel();
    myth.GetTrapframe().MakeUnwinderSysret(myth, out_tf);
    __switch_and_interrupt_enable(&out_tf);
  }

  uintr_frame->AttachXstate(xsave_buf);
  UintrTf tf(uintr_frame);

  uint64_t rsp = uintr_frame->GetRsp() - kRedzoneSize;
  FunctionCallTf &out_tf = FunctionCallTf::CreateOnSyscallStack(myth);
  bool applied = ApplyAllSignals(myth, &rsp, tf, out_tf.GetFrame());

  if (myth.get_process().is_stopped()) {
    // If process is stopped, return via sysret exit loop so we can pause.

    Trapframe *new_entry_frame;

    if (applied) {
      new_entry_frame = &out_tf;
    } else {
      uint64_t sysstack = myth.get_syscall_stack_rsp();
      new_entry_frame = &tf.CloneTo(&sysstack);
    }

    thread_tf jmp_tf;
    myth.mark_enter_kernel();

    new_entry_frame->MakeUnwinderSysret(myth, jmp_tf);
    __switch_and_interrupt_enable(&jmp_tf);
    std::unreachable();
  }

  // Not stopped, so we can jump directly into the signal handler.
  // TODO(jf): make this use UIRET.
  if (applied) {
    __switch_and_interrupt_enable(&out_tf.GetFrame());
    std::unreachable();
  }

  // Nothing happened, return so the state can be restored.
  return;
}

inline bool __nofp InterruptNeeded(thread_t *th) {
  if (ACCESS_ONCE(th->interrupt_state.cnt)) return true;

  struct kthread *k = perthread_read(mykthread);
  return preempt_cede_needed(k) | preempt_yield_needed(k);
}

extern "C" __nofp void uintr_entry(u_sigframe *uintr_frame) {
  void *xsave_buf = nullptr;
  size_t buf_sz;

  assert_stack_is_aligned();
  assert_on_uintr_stack();

  STAT(PREEMPTIONS)++;

  // resume execution if preemption is disabled.
  if (!preempt_enabled() ||
      unlikely(IsOnRuntimeStack(uintr_frame->rsp) || !xsave_enabled_bitmap)) {
    perthread_andi(preempt_cnt, 0x7fffffff);
    return;
  }

  // Take care here to avoid calling functions not marked as __nofp. (The
  // compiler will allow you to do this without complaining.)

  thread_t *th = perthread_read(__self);
  stack &syscall_stack = *th->stack;

  // Check if we need to deliver signals or yield/cede.
  if (!InterruptNeeded(th)) return;

  const uint64_t in_use_xfeatures = GetActiveXstates();
  assert((in_use_xfeatures & xsave_enabled_bitmap) == in_use_xfeatures);

  bool was_xsave_area_used = th->xsave_area_in_use;

  // try to use the per-uthread xsave area. when signals are stacked this may
  // not be possible.
  if (!was_xsave_area_used) {
    xsave_buf = GetXsaveArea(syscall_stack);
    th->xsave_area_in_use = true;
  }

  buf_sz = GetXsaveAreaSize(in_use_xfeatures);

  if (th->junction_thread && uintr_frame->uirrv == SIGURG - 1) {
    if (th->in_syscall) {
      th->xsave_area_in_use = was_xsave_area_used;
      return;
    }

    if (!xsave_buf) {
      // Temporarily save xstate on the UINTR stack. HandleKick will copy it if
      // a signal is delivered.
      uint64_t this_rsp =
          reinterpret_cast<uint64_t>(alloca(buf_sz + kXsaveAlignment - 1));
      // AlignUp
      this_rsp = AlignUp(this_rsp, kXsaveAlignment);
      xsave_buf = reinterpret_cast<void *>(this_rsp);
    }

    XSaveCompact(xsave_buf, in_use_xfeatures, buf_sz);

    // Use a function that is not marked nofp to perform the remaining
    // operations.
    HandleKickUintrFinish(th, uintr_frame, xsave_buf, was_xsave_area_used);

    // If we return to this point, restore the floating point state.
    uintr_frame->RestoreXstate();
    th->xsave_area_in_use = was_xsave_area_used;
    return;
  }

  // We need to determine where we should place xstate before saving it.
  // If this interrupt landed on a non-Junction thread, place the xstate
  // directly on the interrupted stack. If this interrupt landed on a Junction
  // thread, place the xstate onto the syscall stack.
  uint64_t rsp = uintr_frame->rsp - kRedzoneSize;
  if (th->junction_thread && !IsOnStack(rsp, syscall_stack))
    rsp = GetSyscallStackBottom(syscall_stack);

  if (!xsave_buf) {
    // Allocate space on the target stack for the xsave.
    // AlignDown:
    rsp = AlignDown(rsp - buf_sz, kXsaveAlignment);
    xsave_buf = reinterpret_cast<void *>(rsp);
  }

  XSaveCompact(xsave_buf, in_use_xfeatures, buf_sz);

  // Safe to use regular functions now that we have done an XSave.
  UintrFinishYield(uintr_frame, th, xsave_buf, rsp, was_xsave_area_used);

  __builtin_unreachable();
}

// Signal handler for IOKernel sent signals (SIGUSR1 + SIGUSR2)
// Also handles SIGURG to deliver pending signals
extern "C" void caladan_signal_handler(int signo, siginfo_t *info,
                                       void *context) {
  STAT(PREEMPTIONS)++;

  assert(!uintr_enabled);
  assert_stack_is_aligned();

  auto *uc = k_sigframe::FromUcontext(reinterpret_cast<k_ucontext *>(context));

  // resume execution if preemption is disabled
  if (!preempt_enabled() || unlikely(IsOnRuntimeStack(uc->GetRsp()))) {
    perthread_andi(preempt_cnt, 0x7fffffff);
    return;
  }

  // Preemption is implicitly disabled because we are running on the runtime
  // stack. Update the preempt counter to reflect this, so our return routines
  // can decrement it after switching stacks.
  preempt_disable();
  assert_on_runtime_stack();

  thread_t *th = thread_self();
  thread_tf &out_tf = th->tf;
  NewThreadTf newtf;
  KernelSignalTf sigframe(uc);

  // Mark that this trapframe was not generated by a system call.
  uc->uc.uc_mcontext.trapno = -1UL;

  uint64_t rsp = sigframe.GetRsp() - kRedzoneSize;

  if (IsJunctionThread()) {
    Thread &myth = Thread::fromCaladanThread(th);

    FaultStatus fstatus = GetFaultStatus(myth, rsp, sigframe.GetRip());
    myth.mark_enter_kernel();

    if (fstatus == FaultStatus::kInSyscall) {
      // Will be yielding/cedeing, set up sigframe restore next time
      // this thread is run. Move sigframe to the syscall stack in case the
      // current stack can't tolerate signals. Despite being marked as
      // in_kernel, it is possible that a stack switch for a system call is
      // about to happen.
      rsp = myth.correct_to_syscall_stack(rsp);
      sigframe.CloneTo(&rsp).MakeUnwinder(out_tf);
    } else if (unlikely(fstatus == FaultStatus::kCompletingSyscall)) {
      // Signal was delivered just as the thread is exiting the kernel, rewind
      // the exit and check for signals again.
      myth.GetTrapframe().MakeUnwinderSysret(myth, out_tf);
    } else if (signo == SIGURG &&
               ApplyAllSignals(myth, &rsp, sigframe, newtf)) {
      // A signal was successfully delivered and out_tf has the signal handler,
      // move it to the syscall stack and get a new frame to exit the kernel and
      // unwind that.
      rsp = myth.get_syscall_stack_rsp();
      FunctionCallTf(newtf).CloneTo(&rsp).JmpUnwindSysretPreemptEnable(myth);
      std::unreachable();
    } else {
      // Nothing happened with this signal yet, but we will need to restore it
      // using the sysret unwinder.
      rsp = myth.get_syscall_stack_rsp();
      sigframe.CloneTo(&rsp).MakeUnwinderSysret(myth, out_tf);
    }
  } else {
    sigframe.CloneTo(&rsp).MakeUnwinder(out_tf);
  }

  if (signo == SIGURG) {
    // No need to yield to the scheduler, just return to the interrupted code.
    // If a preempt is pending, we will catch it when re-enabling preemption.
    __switch_and_preempt_enable(&out_tf);
  }

  // restore runtime FS register.
  SetFSBase(perthread_read(runtime_fsbase));

  if (signo == SIGUSR1)
    thread_finish_cede();
  else
    thread_finish_yield();

  std::unreachable();
}

std::optional<k_sigaction> ThreadSignalHandler::GetAction(int sig) {
  Process &p = this_thread().get_process();
  k_sigaction act = p.get_signal_table().get_action(sig, true);

  // parse the type of signal action to perform
  SignalAction action = ParseAction(act, sig);

  switch (action) {
    case SignalAction::kNormal:
      return act;
    case SignalAction::kIgnore:
      return std::nullopt;
    case SignalAction::kStop:
      p.JobControlStop(true);
      return std::nullopt;
    case SignalAction::kTerminate:
    case SignalAction::kCoredump:
      return SigKillAction;
  }

  std::unreachable();
}

void SynchronousKill(Thread &th, const KernelSignalTf &sigframe,
                     int signo = SIGSEGV) {
  uint64_t rsp = th.get_syscall_stack_rsp();
  KernelSignalTf &stack_tf = sigframe.CloneTo(&rsp);
  k_sigframe &new_frame = stack_tf.GetFrame();
  new_frame.uc.uc_mcontext.trapno = EKILLPROC;
  th.mark_enter_kernel();
  th.SetTrapframe(stack_tf);
  new_frame.pretcode = 0;  // Won't return
  nosave_switch_preempt_enable(reinterpret_cast<thread_fn_t>(&usys_exit_group),
                               AlignForFunctionEntry(rsp), 128 + signo);
  std::unreachable();
}

DEFINE_PERTHREAD(const KernelSignalTf *, trapped_frame);

void ThreadSignalHandler::DeliverKernelSigToUser(int signo,
                                                 const KernelSignalTf &sigframe,
                                                 Thread &myth) {
  assert(IsOnStack(GetSyscallStack()) || on_runtime_stack());

  std::optional<k_sigaction> tmp;
  if (likely(!is_sig_blocked(signo)))
    tmp = GetAction(signo);
  else
    LOG(WARN) << "synchronous signal blocked";

  // synchronous signal kills program if no action is specified.
  if (!tmp || tmp->handler == SigKillHandler)
    SynchronousKill(myth, sigframe, signo);

  const k_sigaction &act = *tmp;

  // Determine stack to use
  uint64_t rsp = sigframe.GetRsp() - kRedzoneSize;
  const stack_t &ss = get_altstack();
  if (act.wants_altstack() && has_altstack() && !IsOnStack(rsp, ss))
    rsp = reinterpret_cast<uint64_t>(ss.ss_sp) + ss.ss_size;

  // transfer the frame. This function might fault if there is an issue with the
  // stack, mark the sigframe so we can trap in this case and kill the program.
  perthread_store(trapped_frame, &sigframe);
  k_sigframe *new_frame = sigframe.PushUserVisibleFrame(&rsp);
  perthread_store(trapped_frame, nullptr);

  // fix restorer
  new_frame->pretcode = reinterpret_cast<char *>(act.restorer);

  // fix altstack
  new_frame->uc.uc_stack = get_altstack();

  // disarm sigstack if needed
  if (ss.ss_flags & kSigStackAutoDisarm) DisableAltStack();

  // Mask signals. Because this signal delivery occurs outside of a syscall, we
  // don't need to worry about restoring a saved mask.
  SigProcMask(SIG_BLOCK, &act.sa_mask, &new_frame->uc.mask);

  if (unlikely(GetCfg().strace_enabled())) LogSignal(new_frame->info);

  // setup a trapframe to run the signal handler.
  FunctionCallTf &ftf = FunctionCallTf::CreateOnSyscallStack(myth);
  thread_tf &tf = ftf.GetFrame();
  tf.rsp = reinterpret_cast<uint64_t>(new_frame);
  tf.rip = reinterpret_cast<uint64_t>(act.handler);
  tf.rdi = static_cast<uint64_t>(signo);
  tf.rsi = reinterpret_cast<uint64_t>(&new_frame->info);
  tf.rdx = reinterpret_cast<uint64_t>(&new_frame->uc);

  myth.mark_enter_kernel();
  ftf.JmpUnwindSysretPreemptEnable(myth);
  std::unreachable();
}

// Handle a page fault for a program. Must be called on the syscall stack.
void HandlePageFaultOnSyscallStack(KernelSignalTf &frame, int required_prot,
                                   Time time) {
  Thread &myth = mythread();
  const siginfo_t &info = frame.GetFrame().info;

  assert(!preempt_enabled());
  assert(myth.rsp_on_syscall_stack());

  FaultStatus fstatus = GetFaultStatus(myth, frame.GetRsp(), frame.GetRip());

  // We can re-enable preemption after marking this thread in_kernel.
  // Provide this frame as the kernel entry frame unless one already exists.
  myth.mark_enter_kernel();
  if (fstatus == FaultStatus::kNotInSyscall) myth.SetTrapframe(frame);

  // Re-enable preemption after switching off runtime stack.
  preempt_enable();

  // Give the memory map the first chance to see the page fault.
  bool fault_handled = myth.get_process().get_mem_map().HandlePageFault(
      reinterpret_cast<uintptr_t>(info.si_addr), required_prot, time);

  if (!fault_handled) {
    // We don't expect faults in the Junction kernel; crash.
    if (fstatus != FaultStatus::kNotInSyscall)
      print_msg_abort("unhandled segfault while in Junction syscall handler");

    // Preemption must be disabled before moving data to the syscall stack.
    preempt_disable();

    // Pass the signal to the user defined signal handler. Synchronous signals
    // cannot be blocked, so a handler will be invoked or the program will be
    // killed.
    myth.get_sighand().DeliverKernelSigToUser(SIGSEGV, frame, myth);
    std::unreachable();
  }

  if (fstatus == FaultStatus::kInSyscall) {
    // Restore the frame immediately.
    frame.JmpUnwind();
  } else if (unlikely(fstatus == FaultStatus::kCompletingSyscall)) {
    // signal delivered just as we were returning from a system call, rewind the
    // exit and try again.
    myth.GetTrapframe().JmpUnwindSysret(myth);
  } else {
    // Landed on user code; simulate a syscall exit so we can check for signals.
    frame.JmpUnwindSysret(myth);
  }

  std::unreachable();
}

// Signal handler for synchronous fault signals generated by user code. We
// don't expect there to be recursive signals.
extern "C" void synchronous_signal_handler(int signo, siginfo_t *info,
                                           void *context) {
  assert_on_runtime_stack();
  assert_stack_is_aligned();

  // Record fault time in case the tracer needs it.
  Time time = Time::Now();

  if (unlikely(!context)) print_msg_abort("signal delivered without context");

  if (unlikely(!thread_self()))
    print_msg_abort("Unexpected signal delivered to Caladan code");

  if (unlikely(!IsJunctionThread()))
    print_msg_abort("Unexpected signal delivered to Junction code");

  auto uc = k_sigframe::FromUcontext(reinterpret_cast<k_ucontext *>(context));

  // Mark that this trapframe was not generated by a system call.
  uc->uc.uc_mcontext.trapno = -1UL;

  bool was_preempt_disabled = unlikely(!preempt_enabled());
  // Update preemption counter to reflect that preemption is implicitly disabled
  // when we are on the runtime stack.
  if (!was_preempt_disabled) preempt_disable();

  const KernelSignalTf *prev_tf = perthread_get(trapped_frame);
  perthread_store(trapped_frame, nullptr);

  Thread &myth = mythread();

  // Give the memory map a chance to handle the fault
  if (signo == SIGSEGV) {
    MemoryMap &mm = myth.get_process().get_mem_map();
    int prot = sigsegv_sigcontext_to_prot(uc->uc.uc_mcontext);

    // We might have segfaulted with preemption disabled in the Junction kernel.
    // Not great, but if the page fault handler can fix it, we can keep going.
    if (was_preempt_disabled) {
      // It is only safe to enter the memory map when preemption is disabled if
      // tracing was enabled, since all MM operations are synchronized with a
      // spin lock during tracing.
      if (mm.TraceEnabled() &&
          mm.HandlePageFault(reinterpret_cast<uintptr_t>(info->si_addr), prot,
                             time))
        return;
      // Try to cleanly kill this program.
      if (prev_tf) SynchronousKill(myth, *prev_tf);
      print_msg_abort("signal delivered while preemption is disabled");
    }

    // Prepare to switch from the runtime stack to this thread's syscall stack.
    // This allows the page fault handler to block when waiting for mutexes.
    uint64_t rsp = myth.correct_to_syscall_stack(uc->GetRsp() - kRedzoneSize);

    // Move the Linux trapframe to the syscall stack.
    KernelSignalTf &tf = KernelSignalTf(uc).CloneTo(&rsp);

    RunOnStackAtFromSignalStack(rsp, [=, tf = &tf] mutable {
      HandlePageFaultOnSyscallStack(*tf, prot, time);
    });
    std::unreachable();
  }

  if (unlikely(was_preempt_disabled || IsOnRuntimeStack(uc->GetRsp()))) {
    if (prev_tf) SynchronousKill(myth, *prev_tf);
    print_msg_abort("signal delivered while preemption is disabled");
  }

  if (unlikely(GetFaultStatus(myth, uc->GetRsp(), uc->GetRip()) !=
               FaultStatus::kNotInSyscall))
    print_msg_abort("signal delivered while in Junction syscall handler");

  myth.get_sighand().DeliverKernelSigToUser(signo, KernelSignalTf(uc), myth);
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

  assert(signo != SIGCONT);

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

// Unwind a sigframe from a Junction process's thread.
// Note Linux's rt_sigreturn expects the sigframe to be on the stack.
// Our rt_sigreturn assembly target switches stacks and calls this function with
// the old rsp as an argument.
extern "C" [[noreturn]] void usys_rt_sigreturn_finish(uint64_t rsp) {
  assert_stack_is_aligned();
  assert_preempt_disabled();
  assert(rsp % 16 == 0);

  Thread &myth = mythread();

  k_sigframe *sigframe = reinterpret_cast<k_sigframe *>(rsp - 8);
  JunctionSigframe *jframe =
      reinterpret_cast<JunctionSigframe *>(rsp - 8 + sizeof(*sigframe));
  ThreadSignalHandler &hand = myth.get_sighand();

  if (unlikely(jframe->magic != kJunctionFrameMagic))
    print_msg_abort("invalid stack frame used in rt_sigreturn");

  if (unlikely(GetCfg().strace_enabled())) LogSyscall("rt_sigreturn");

  // set blocked
  hand.ReplaceMask(sigframe->uc.mask);

  // update altstack
  hand.SigAltStack(&sigframe->uc.uc_stack, nullptr);

  myth.mark_enter_kernel();
  uint64_t out_rsp = myth.get_syscall_stack_rsp();

  // Unwind.
  Trapframe &tf = jframe->CloneTo(&out_rsp);
  thread_tf unwind;
  tf.MakeUnwinderSysret(myth, unwind);
  __switch_and_preempt_enable(&unwind);
  std::unreachable();
}

// Find next signal pending in either the thread or proc siqueues.
std::optional<siginfo_t> ThreadSignalHandler::PopSigInfo(
    k_sigset_t blocked, bool reset_flag = true) {
  std::optional<siginfo_t> tmp;

  // Make sure sig_q_ lock is never acquired while holding shared_q lock
  rt::SpinGuard g(sig_q_);
  tmp = sig_q_.Pop(blocked);
  if (tmp) return tmp;

  {
    rt::SpinGuard g(shared_q_);

    // Check for SIGSTOP
    if (this_thread().get_process().is_stopped()) return std::nullopt;

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

ThreadSignalHandler::ThreadSignalHandler(Thread &thread,
                                         const ThreadSignalHandler &clone_hand)
    : shared_q_(thread.get_process().get_signal_queue()),
      blocked_(clone_hand.get_blocked_mask()),
      mythread_(thread){};

ThreadSignalHandler::ThreadSignalHandler(Thread &thread)
    : shared_q_(thread.get_process().get_signal_queue()), mythread_(thread){};

// Find next actionable signal
std::optional<DeliveredSignal> ThreadSignalHandler::GetNextSignal() {
  DeliveredSignal sig;

  while (true) {
    std::optional<siginfo_t> info = PopSigInfo(blocked_, true);
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

// Called by the Caladan scheduler when a Junction thread is being scheduled.
extern "C" void on_sched(thread_t *th) {
  assert(th->junction_thread);
  Thread &myth = Thread::fromCaladanThread(th);
  myth.get_rseq().fixup(myth);
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
void ThreadSignalHandler::DeliverSignals(Trapframe &entry, long rax) {
  assert(&mythread() == &this_thread());
  assert(&entry == &mythread().GetTrapframe());
  std::optional<DeliveredSignal> sig;
  Thread &myth = this_thread();
  assert(myth.in_kernel());

  // Check for signals or job control STOPs.
  while (true) {
    sig = GetNextSignal();

    // We found a handled signal, break out of the loop and proceed.
    if (sig) break;

    // Park the thread here if stopping.
    if (myth.get_process().is_stopped()) {
      // This thread should already have a non-zero interrupt state, but this
      // clears the prepared flag to allow the thread to block again on the
      // stopped threads WaitQueue.
      set_interrupt_state_interrupted();
      myth.StopWait(rax);
      continue;
    }

    // Check if we need to restart the system call.
    if (!IsRestartSys(rax)) return;
    myth.GetSyscallFrame().JmpRestartSyscall();
    std::unreachable();
  }

  if (IsRestartSys(rax))
    CheckRestartSysPostHandler(myth.GetSyscallFrame(), rax, *sig);

  // Abort an rseq CS if needed.
  myth.get_rseq().fixup(myth, &entry);

  RunOnSyscallStack([this, d = *sig, entry = &entry]() mutable {
    // HACK: entry might be sitting on top of this RSP, will need a better a
    // solution, but for now just try to avoid the area immediately above RSP.
    uint64_t rsp =
        entry->GetRsp() - std::max(kRedzoneSize, 2 * sizeof(thread_tf));

    NewThreadTf sighand_tf;

    PushUserSigFrame(d, &rsp, *entry, sighand_tf);

    Thread &myth = mythread();
    Process &p = myth.get_process();

    // Set sighand_tf as the kernel entry trapframe.
    FunctionCallTf &frame = myth.ReplaceEntryRegs(sighand_tf);

    while (true) {
      std::optional<DeliveredSignal> d = GetNextSignal();
      if (!d) {
        if (p.is_stopped()) {
          set_interrupt_state_interrupted();
          myth.StopWait(0);
          continue;
        }
        break;
      }

      PushUserSigFrame(*d, &rsp, frame, sighand_tf);
    }

    frame.JmpUnwindSysret(myth);
    std::unreachable();
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
  // Fast path.
  if (tgid == myproc().get_pid()) {
    myproc().Signal(sig);
    return 0;
  };

  // Determine type of identifier used.
  auto [idtype, id] = PidtoId(tgid);
  if (idtype == P_PID) {
    std::shared_ptr<Process> proc = Process::Find(id);
    if (!proc) return -ESRCH;
    proc->Signal(sig);
    return 0;
  }

  // Signal all procs in process group
  if (idtype == P_PGID) {
    if (id == 0) id = myproc().get_pgid();
    size_t cnt = 0;
    Process::ForEachProcess([&](Process &p) {
      if (p.get_pgid() == static_cast<pid_t>(id)) {
        p.Signal(sig);
        cnt++;
      }
    });
    return cnt > 0 ? 0 : -ESRCH;
  }

  // Signal all procs.
  Process::ForEachProcess([&](Process &p) { p.Signal(sig); });
  return 0;
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

long usys_rt_sigtimedwait(const sigset_t *set, siginfo_t *info,
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

long usys_rt_sigsuspend(const sigset_t *set, size_t sigsetsize) {
  if (unlikely(sigsetsize != sizeof(k_sigset_t))) return -EINVAL;

  const k_sigset_t *mask = reinterpret_cast<const k_sigset_t *>(set);

  ThreadSignalHandler &hand = mythread().get_sighand();
  hand.ReplaceAndSaveBlocked(*mask);

  rt::Preempt p;
  rt::ThreadWaker w;
  rt::UniqueLock<rt::Preempt> g(p);
  rt::WaitInterruptibleNoRecheck(std::move(g), w);

  return -ERESTARTNOHAND;
}

long usys_pause() {
  rt::Preempt p;
  rt::ThreadWaker w;
  rt::UniqueLock<rt::Preempt> g(p);
  rt::WaitInterruptibleNoRecheck(std::move(g), w);
  return -ERESTARTNOHAND;
}

extern "C" void RunSignals(long rax) {
  assert_stack_is_aligned();
  Thread &th = mythread();
  th.get_sighand().DeliverSignals(th.GetTrapframe(), rax);
}

Status<void> InitSignal() {
  Status<void> ret = InitXsave();
  if (!ret) return ret;

  struct sigaction act;
  sigemptyset(&act.sa_mask);
  act.sa_sigaction = synchronous_signal_handler;
  act.sa_flags = SA_ONSTACK | SA_SIGINFO | SA_NODEFER;

  if (uintr_enabled)
    act.sa_restorer = &__kframe_unwind_uiret;
  else
    act.sa_restorer = &syscall_rt_sigreturn;

  // Only synchronous signals need be delivered by the host kernel. Other
  // signal numbers will be emulated fully inside Junction.
  for (size_t sig = 1; sig <= kNumStandardSignals; sig++) {
    if (!SignalInMask(kSignalSynchronousMask, sig)) continue;
    if (unlikely(base_sigaction_full(sig, &act, nullptr) != 0))
      return MakeError(errno);
  }

  // Replace Caladan sighandler with one that receives signals on
  // alternate stacks and transfers frames to the correct altstacks
  act.sa_sigaction = caladan_signal_handler;
  for (auto sig : {SIGUSR1, SIGUSR2, SIGURG}) {
    if (unlikely(base_sigaction_full(sig, &act, nullptr) != 0)) {
      return MakeError(errno);
    }
  }

  return {};
}

}  // namespace junction
