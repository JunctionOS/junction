
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

}  // namespace junction