
#include "junction/kernel/trapframe.h"

#include <cstring>

#include "junction/kernel/proc.h"
#include "junction/syscall/syscall.h"
#include "junction/syscall/systbl.h"

namespace junction {

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

void KernelSignalTf::MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) {
  th.SetTrapframe(*this);
  unwind_tf.rip = reinterpret_cast<uint64_t>(__kframe_unwind_loop);
  unwind_tf.rsp = reinterpret_cast<uint64_t>(&sigframe.uc);
  unwind_tf.rdi = 0;  // argument for RunSignals
  // Stack aligned to allow assembly code to make function calls without
  // aligning the stack.
  assert(unwind_tf.rsp % kStackAlign == 0);
}

[[noreturn]] void KernelSignalTf::JmpRestartSyscall() {
  thread_tf tf;
  sigcontext &ctx = sigframe.uc.uc_mcontext;

  sigframe.pretcode = reinterpret_cast<char *>(__syscall_trap_return);

  // can ignore caller-saved registers for the trap entry path
  tf.rax = GetOrigRax();
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
  uint64_t sp = reinterpret_cast<uint64_t>(&sigframe.uc);
  // 0 argument provided for RunSignals.
  nosave_switch(reinterpret_cast<thread_fn_t>(__kframe_unwind_loop), sp,
                0 /* rdi */);
}

FunctionCallTf &FunctionCallTf::CreateOnSyscallStack(Thread &th) {
  // It is only safe to place data on the syscall stack (without also running on
  // it) if preemption is disabled.
  assert(!th.GetCaladanThread()->thread_running || !preempt_enabled() ||
         (uintr_enabled && !TestUIF()));
  uint64_t rsp = th.get_syscall_stack_rsp();
  FunctionCallTf *stack_wrapper = AllocateOnStack<FunctionCallTf>(&rsp);
  thread_tf *stack_tf = AllocateOnStack<thread_tf>(&rsp);
  InitializeThreadTf(*stack_tf);
  new (stack_wrapper) FunctionCallTf(stack_tf);
  return *stack_wrapper;
}

uint64_t RewindIndirectSystemCall(uint64_t rip) {
  static const uint8_t imm[] = {0xff, 0x14, 0x25};
  const uint8_t *insns = reinterpret_cast<uint8_t *>(rip);

  // call *(imm): ff 14 25 28 0e 20 00    call   *0x200e28
  // call *(rax):                ff d0    call   *%rax

  static_assert(SYSTBL_TRAMPOLINE_LOC >> 16 == 0x20);
  // The 7-byte immediate variant will have a 0x20 at rip - 2 regardless of
  // which entry point was used. The 2-byte register variant will have an 0xff
  // at this position.
  bool is_reg_operand = *(insns - 2) == 0xff;

  // NOTE: the register variant is not supported with snapshotting and we are
  // trying to avoid generating it in glibc.
  // NOTE 2: the register variant is used for zpoline though.
  assert(!is_reg_operand);

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
  tf->rax = GetOrigRax();
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
  assert_stack_is_aligned();
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

    // Doesn't return if a signal is delivered.
    myth.get_sighand().DeliverSignals(*frame, 0);
  }
}

void FunctionCallTf::MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) {
  th.SetTrapframe(*this);
  unwind_tf.rsp = reinterpret_cast<uint64_t>(tf);
  unwind_tf.rip = GetSysretUnwinderFunction();
  // Stack aligned to allow assembly code to make function calls without
  // aligning the stack.
  assert(unwind_tf.rsp % kStackAlign == 0);
}

[[noreturn]] void UintrTf::JmpUnwindSysret(Thread &th) {
  assert(&th == &mythread());
  assert(th.in_kernel());
  th.SetTrapframe(*this);
  uint64_t rdi = reinterpret_cast<uint64_t>(this);
  uint64_t rsp = AlignForFunctionEntry(reinterpret_cast<uint64_t>(&sigframe));
  nosave_switch(reinterpret_cast<thread_fn_t>(UintrLoopReturn), rsp, rdi);
}

void UintrTf::MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) {
  th.SetTrapframe(*this);
  unwind_tf.rdi = reinterpret_cast<uint64_t>(this);
  unwind_tf.rsp = AlignForFunctionEntry(reinterpret_cast<uint64_t>(&sigframe));
  unwind_tf.rip = reinterpret_cast<uint64_t>(UintrLoopReturn);
}

void KernelSignalTf::DoSave(cereal::BinaryOutputArchive &ar, int rax) const {
  ar(SigframeType::kKernelSignal);
  if (IsRestartSys(rax)) {
    // Copy the frame, update it to restart the system call. The pointer to the
    // xstate is still valid, so no need to copy/update that.
    k_sigframe copy = sigframe;
    // restore rax
    copy.uc.uc_mcontext.rax = GetOrigRax();
    // go back to syscall instruction
    copy.uc.uc_mcontext.rip -= 2;
    copy.DoSave(ar);
  } else {
    sigframe.DoSave(ar);
  }
}

void FunctionCallTf::DoSave(cereal::BinaryOutputArchive &ar, int rax) const {
  ar(SigframeType::kJunctionTf);

  size_t xsave_len = 0;
  if (tf->xsave_area) {
    xsave_len = GetXsaveAreaSize(reinterpret_cast<xstate *>(tf->xsave_area));
    ar(xsave_len);
    ar(cereal::binary_data(tf->xsave_area, xsave_len));
  } else {
    ar(xsave_len);
  }

  if (IsRestartSys(rax)) {
    thread_tf copy = *tf;
    copy.rax = GetOrigRax();
    copy.rip = RewindIndirectSystemCall(tf->rip);
    ar(copy);
  } else {
    ar(*tf);
  }
}

void UintrTf::DoSave(cereal::BinaryOutputArchive &ar, int rax) const {
  ar(SigframeType::kJunctionUIPI);
  assert(!IsRestartSys(rax));
  sigframe.DoSave(ar);
}

void LoadTrapframe(cereal::BinaryInputArchive &ar, Thread *th) {
  uint64_t stack_bottom = th->get_syscall_stack_rsp();
  SigframeType trapframe_type;
  ar(trapframe_type);

  Trapframe *tf;

  switch (trapframe_type) {
    case SigframeType::kKernelSignal:
      tf = KernelSignalTf::DoLoad(ar, &stack_bottom);
      break;
    case SigframeType::kJunctionUIPI:
      tf = UintrTf::DoLoad(ar, &stack_bottom);
      break;
    case SigframeType::kJunctionTf:
      tf = FunctionCallTf::DoLoad(ar, &stack_bottom);
      break;
    default:
      BUG();
      break;
  }

  tf->MakeUnwinderSysret(*th, th->GetCaladanThread()->tf);
}

Trapframe &JunctionSigframe::CloneTo(uint64_t *rsp) {
  switch (type) {
    case SigframeType::kKernelSignal:
      return KernelSignalTf(reinterpret_cast<k_sigframe *>(tf)).CloneTo(rsp);
    case SigframeType::kJunctionUIPI:
      return UintrTf(reinterpret_cast<u_sigframe *>(tf)).CloneTo(rsp);
    case SigframeType::kJunctionTf:
      return FunctionCallTf(reinterpret_cast<thread_tf *>(tf)).CloneTo(rsp);
    default:
      BUG();
  }
}

}  // namespace junction
