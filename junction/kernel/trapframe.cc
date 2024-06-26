
#include "junction/kernel/trapframe.h"

#include <cstring>

#include "junction/kernel/proc.h"
#include "junction/syscall/syscall.h"
#include "junction/syscall/systbl.h"

namespace junction {

template <typename Tf>
void DoCopy(thread_tf &newtf, const Tf &oldtf) {
  newtf.rdi = oldtf.rdi;
  newtf.rsi = oldtf.rsi;
  newtf.rdx = oldtf.rdx;
  newtf.rcx = oldtf.rcx;
  newtf.r8 = oldtf.r8;
  newtf.r9 = oldtf.r9;
  newtf.r10 = oldtf.r10;
  newtf.r11 = oldtf.r11;
  newtf.rbx = oldtf.rbx;
  newtf.rbp = oldtf.rbp;
  newtf.r12 = oldtf.r12;
  newtf.r13 = oldtf.r13;
  newtf.r14 = oldtf.r14;
  newtf.r15 = oldtf.r15;
  newtf.rsp = oldtf.rsp;
  newtf.rip = oldtf.rip;
}

void KernelSignalTf::CopyRegs(thread_tf &dest_tf) const {
  DoCopy(dest_tf, sigframe.uc.uc_mcontext);
}

void FunctionCallTf::CopyRegs(thread_tf &dest_tf) const {
  DoCopy(dest_tf, *tf);
}

k_sigframe *KernelSignalTf::PushUserVisibleFrame(uint64_t *rsp) const {
  // transfer the frame
  void *fx_buf = sigframe.CopyXstateToStack(rsp);

  // add a junction frame between xstate and ucontext
  JunctionSigframe *jframe = AllocateOnStack<JunctionSigframe>(rsp);
  jframe->magic = kJunctionFrameMagic;

  // copy ucontext, siginfo, etc
  k_sigframe *new_frame = sigframe.CopyToStack(rsp, fx_buf);

  jframe->type = SigframeType::kKernelSignal;
  jframe->tf = new_frame;
  return new_frame;
}

// Restore a kernel signal frame upon system call exit. When UINTR is enabled,
// this can be done with no system calls.
extern "C" [[noreturn]] void UintrKFrameLoopReturn(k_sigframe *frame,
                                                   uint64_t rax) {
  Thread &myth = mythread();

  while (true) {
    ClearUIF();
    myth.mark_leave_kernel();
    if (!myth.needs_interrupt()) {
      nosave_switch(
          reinterpret_cast<thread_fn_t>(__kframe_unwind_uiret),
          reinterpret_cast<uint64_t>(frame) + offsetof(k_sigframe, uc), 0);
      std::unreachable();
    }

    // a signal slipped in, handle it and try again
    myth.mark_enter_kernel();
    SetUIF();

    myth.get_sighand().DeliverSignals(myth.GetTrapframe(), rax);
    rax = 0;
  }
}

void KernelSignalTf::ResetRestartRax() {
  if (is_from_syscall() && IsRestartSys(sigframe.uc.uc_mcontext.rax))
    sigframe.uc.uc_mcontext.rax = -EINTR;
}

void KernelSignalTf::MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) {
  th.SetTrapframe(*this);
  if (uintr_enabled) {
    // Ensure syscall return value is 0.
    unwind_tf.rsi = 0;
    // align stack and set to to beginning of sigframe
    unwind_tf.rsp = reinterpret_cast<uint64_t>(&sigframe);
    unwind_tf.rdi = unwind_tf.rsp;
    unwind_tf.rip = reinterpret_cast<uint64_t>(UintrKFrameLoopReturn);
    assert(unwind_tf.rsp % 16 == 8);
  } else {
    // __kframe_unwind_loop will provide a zero argument to RunSignals.
    unwind_tf.rip = reinterpret_cast<uint64_t>(__kframe_unwind_loop);
    unwind_tf.rsp = reinterpret_cast<uint64_t>(&sigframe.uc);
  }
}

[[noreturn]] void KernelSignalTf::JmpRestartSyscall() {
  thread_tf tf;
  sigcontext &ctx = sigframe.uc.uc_mcontext;

  if (uintr_enabled)
    sigframe.pretcode = reinterpret_cast<char *>(__syscall_trap_return_uintr);
  else
    sigframe.pretcode = reinterpret_cast<char *>(__syscall_trap_return);

  // can ignore caller-saved registers for the trap entry path
  tf.rax = ctx.trapno;
  tf.rsp = reinterpret_cast<uint64_t>(&sigframe);
  tf.rdi = ctx.rdi;
  tf.rsi = ctx.rsi;
  tf.rdx = ctx.rdx;
  tf.r8 = ctx.r8;
  tf.r9 = ctx.r9;
  tf.rcx = ctx.r10;
  assert(tf.rax < SYS_NR);
  tf.rip = reinterpret_cast<uint64_t>(sys_tbl[tf.rax]);
  __jmp_syscall_restart_nosave(&tf);
}

[[noreturn]] void KernelSignalTf::JmpUnwindSysret(Thread &th) {
  assert(&th == &mythread());
  assert(th.in_kernel());
  th.SetTrapframe(*this);

  sigframe.InvalidateAltStack();
  sigframe.uc.mask = 0;

  if (uintr_enabled) {
    uint64_t sp = reinterpret_cast<uint64_t>(&sigframe);
    assert(sp % 16 == 8);
    nosave_switch(reinterpret_cast<thread_fn_t>(UintrKFrameLoopReturn), sp, sp);
  } else {
    uint64_t sp = reinterpret_cast<uint64_t>(&sigframe.uc);
    // __kframe_unwind_loop will provide a zero argument to RunSignals.
    nosave_switch(reinterpret_cast<thread_fn_t>(__kframe_unwind_loop), sp, 0);
  }
}

FunctionCallTf &FunctionCallTf::CreateOnSyscallStack(Thread &th) {
  // It is only safe to place data on the syscall stack (without also running on
  // it) if preemption is disabled.
  assert(!th.GetCaladanThread()->thread_running || !preempt_enabled() ||
         (uintr_enabled && !TestUIF()));
  uint64_t rsp = th.get_syscall_stack_rsp();
  FunctionCallTf *stack_wrapper = AllocateOnStack<FunctionCallTf>(&rsp);
  thread_tf *stack_tf = AllocateOnStack<thread_tf>(&rsp);
  new (stack_wrapper) FunctionCallTf(stack_tf);
  return *stack_wrapper;
}

void FunctionCallTf::ResetRestartRax() {
  if (is_from_syscall() && IsRestartSys(tf->rax)) tf->rax = -EINTR;
}

uint64_t RewindIndirectSystemCall(uint64_t rip) {
  static const uint8_t imm[] = {0xff, 0x14, 0x25};
  const uint8_t *insns = reinterpret_cast<uint8_t *>(rip);

  // call *(imm): ff 14 25 28 0e 20 00    call   *0x200e28
  // call *(rax):                ff d0    call   *%rax

  static_assert(SYSTBL_TRAMPOLINE_LOC >> 16 == 0x20);
  // The 7-byte immediate variant will have a 0x20 at rip - 2 regardless of
  // which entry point was used. The 2-byte register variant will have an 0xff
  // at this position
  bool is_reg_operand = *(insns - 2) == 0xff;

  // check for debug purposes only
  bool is_imm_operand = memcmp(imm, insns - 7, 3) == 0;
  assert(is_imm_operand ^ is_reg_operand);

  if (is_reg_operand)
    return rip - 2;
  else
    return rip - 7;
}

void FunctionCallTf::ResetToSyscallStart() {
  tf->rip = RewindIndirectSystemCall(tf->rip);
  tf->rax = tf->orig_rax;
}

[[noreturn]] void FunctionCallTf::JmpRestartSyscall() {
  ResetToSyscallStart();
  __jmp_syscall_restart_nosave(tf);
}

[[noreturn]] void FunctionCallTf::JmpUnwindSysret(Thread &th) {
  assert(&th == &mythread());
  assert(th.in_kernel());
  th.SetTrapframe(*this);
  nosave_switch(reinterpret_cast<thread_fn_t>(GetSysretUnwinderFunction()),
                reinterpret_cast<uint64_t>(tf), 0);
}

[[noreturn]] void FunctionCallTf::JmpUnwindSysretPreemptEnable(Thread &th) {
  assert_preempt_disabled();
  assert(&th == &mythread());
  assert(th.in_kernel());
  th.SetTrapframe(*this);
  nosave_switch_preempt_enable(
      reinterpret_cast<thread_fn_t>(GetSysretUnwinderFunction()),
      reinterpret_cast<uint64_t>(tf), 0);
}

extern "C" [[noreturn]] void UintrLoopReturn(UintrTf *frame) {
  Thread &myth = mythread();

  while (true) {
    ClearUIF();
    myth.mark_leave_kernel();
    if (!myth.needs_interrupt()) {
      UintrFullRestore(&frame->GetFrame());
      std::unreachable();
    }

    // a signal slipped in, handle it and try again
    myth.mark_enter_kernel();
    SetUIF();

    myth.get_sighand().DeliverSignals(*frame, 0);
  }
}

void FunctionCallTf::MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) {
  th.SetTrapframe(*this);
  unwind_tf.rsp = reinterpret_cast<uint64_t>(tf);
  unwind_tf.rip = GetSysretUnwinderFunction();
}

[[noreturn]] void UintrTf::JmpUnwindSysret(Thread &th) {
  assert(&th == &mythread());
  assert(th.in_kernel());
  th.SetTrapframe(*this);
  uint64_t rdi = reinterpret_cast<uint64_t>(this);
  uint64_t rsp = AlignDown(reinterpret_cast<uint64_t>(&sigframe), 16) - 8;
  nosave_switch(reinterpret_cast<thread_fn_t>(UintrLoopReturn), rsp, rdi);
}

void UintrTf::MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) {
  th.SetTrapframe(*this);
  unwind_tf.rdi = reinterpret_cast<uint64_t>(this);
  unwind_tf.rsp = AlignDown(reinterpret_cast<uint64_t>(&sigframe), 16) - 8;
  unwind_tf.rip = reinterpret_cast<uint64_t>(UintrLoopReturn);
}

void LoadTrapframe(cereal::BinaryInputArchive &ar, Thread *th) {
  uint64_t stack_bottom = th->get_syscall_stack_rsp();
  SigframeType trapframe_type;
  ar(trapframe_type);

  KernelSignalTf *ktf;
  FunctionCallTf *ftf;
  Trapframe *tf;

  switch (trapframe_type) {
    case SigframeType::kKernelSignal:
      tf = ktf = KernelSignalTf::DoLoad(ar, &stack_bottom);
      ktf->ResetRestartRax();
      break;
    case SigframeType::kJunctionUIPI:
      tf = UintrTf::DoLoad(ar, &stack_bottom);
      break;
    case SigframeType::kJunctionTf:
      tf = ftf = FunctionCallTf::DoLoad(ar, &stack_bottom);
      ftf->ResetRestartRax();
      break;
    default:
      BUG();
      break;
  }

  tf->MakeUnwinderSysret(*th, th->GetCaladanThread()->tf);
}

}  // namespace junction
