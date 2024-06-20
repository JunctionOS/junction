#pragma once

extern "C" {
#include <base/syscall.h>
}

#include <optional>

#include "junction/base/arch.h"
#include "junction/bindings/stack.h"
#include "junction/bindings/thread.h"
#include "junction/kernel/sigframe.h"
#include "junction/snapshot/cereal.h"
#include "junction/syscall/syscall.h"

inline constexpr uint64_t kJunctionFrameMagic = 0x696e63656e64696fUL;
inline constexpr size_t kJunctionFrameAlign = 16;

namespace junction {

class Thread;

enum class SigframeType : unsigned long {
  kKernelSignal = 0,
  kJunctionUIPI,
  kJunctionTf,
};

// Frame pushed to stack when delivering signals to the user.
struct alignas(kJunctionFrameAlign) JunctionSigframe {
  SigframeType type;
  void *tf;
  unsigned long magic;
  unsigned long pad;

  void Unwind();
};

class Thread;

class Trapframe {
 public:
  // Get the RSP from this trapframe.
  [[nodiscard]] virtual uint64_t GetRsp() const = 0;

  // Copy this trapframe to a new stack, returns a reference to the new
  // instance.
  virtual Trapframe &CloneTo(uint64_t *rsp) const = 0;

  // Clone this trapframe onto a signal handler stack with a Sigframe to unwind
  // it.
  virtual JunctionSigframe &CloneSigframe(uint64_t *rsp) const = 0;

  // Immediately restores this trapframe. Expects preemption to be disabled.
  [[noreturn]] virtual void JmpUnwindPreemptEnable() = 0;

  // Immediately restores this trapframe, exiting the Junction kernel and
  // checking for signals. Expects preemption to be enabled.
  [[noreturn]] virtual void JmpUnwindSysret(Thread &th) = 0;

  // Set up @unwind_tf to unwind this trapframe after performing a final check
  // for pending signals. Unwinders here cannot assume that the frame is a
  // system call and therefore must not pass a non-zero argument to RunSignals.
  // This trapframe instance is attached to @th and must reside on the syscall
  // stack.
  virtual void MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) = 0;

  virtual void DoSave(cereal::BinaryOutputArchive &ar) const = 0;
};

// Trapframes that are created via system call entry to the Junction kernel.
class SyscallFrame : virtual public Trapframe {
 public:
  // Immediately restart this system call.
  [[noreturn]] virtual void JmpRestartSyscall() = 0;

  // Modify the trapframe to repeat the system call when restored.
  virtual void ResetToSyscallStart() = 0;

  // Reset a possible ERESTARTSYS to EINTR.
  virtual void ResetRestartRax() = 0;

  // Mark this trapframe as a non-syscall trapframe (ie from an interrupt).
  virtual void ClearSyscallNr() = 0;

  // Check if this trapframe resulted from a system call or interrupt.
  [[nodiscard]] virtual bool is_from_syscall() const = 0;

  // Set the value for RAX in this trapframe.
  virtual void SetRax(uint64_t rax,
                      std::optional<uint64_t> rsp = std::nullopt) = 0;

  // Copies registers to @dest_tf.
  virtual void CopyRegs(thread_tf &dest_tf) const = 0;

  virtual SyscallFrame &CloneTo(uint64_t *rsp) const override = 0;
};

// Kernel signals are used both for interrupts and to trap syscall instructions.
class KernelSignalTf : public SyscallFrame {
 public:
  KernelSignalTf(k_sigframe &sigframe) : sigframe(sigframe) {}
  KernelSignalTf(k_sigframe *sigframe) : sigframe(*sigframe) {}
  KernelSignalTf(k_ucontext *uc) : sigframe(*k_sigframe::FromUcontext(uc)) {}
  KernelSignalTf(const KernelSignalTf &tf) : sigframe(tf.sigframe) {}

  // When kernel signals are used for interrupts instead of UIPIs, there exists
  // a race condition when unwinding signal frames.
  constexpr static bool HasStackSwitchRace() { return true; }

  // Returns a reference to the underlying sigframe.
  [[nodiscard]] inline k_sigframe &GetFrame() { return sigframe; }

  void CopyRegs(thread_tf &dest_tf) const override;

  JunctionSigframe &CloneSigframe(uint64_t *rsp) const override {
    k_sigframe *stack_tf = sigframe.CopyToStack(rsp);
    JunctionSigframe *jframe = AllocateOnStack<JunctionSigframe>(rsp);
    jframe->type = SigframeType::kKernelSignal;
    jframe->tf = stack_tf;
    jframe->magic = kJunctionFrameMagic;
    return *jframe;
  }

  KernelSignalTf &CloneTo(uint64_t *rsp) const override {
    KernelSignalTf *stack_wrapper = AllocateOnStack<KernelSignalTf>(rsp);
    k_sigframe *stack_tf = sigframe.CopyToStack(rsp);
    new (stack_wrapper) KernelSignalTf(stack_tf);
    return *stack_wrapper;
  }

  // Push this instance to the stack in such a way that it can be directly
  // exposed to the user (JunctionFrame placed between the k_sigframe and
  // xstate).
  k_sigframe *PushUserVisibleFrame(uint64_t *rsp) const;

  void SetRax(uint64_t rax, std::optional<uint64_t> rsp) override {
    sigframe.uc.uc_mcontext.rax = rax;
    if (rsp) sigframe.uc.uc_mcontext.rsp = *rsp;
  }

  void ResetRestartRax() override;

  [[nodiscard]] bool is_from_syscall() const override {
    return static_cast<size_t>(sigframe.uc.uc_mcontext.trapno) < 4096;
  }

  void ClearSyscallNr() override {
    sigframe.uc.uc_mcontext.trapno = std::numeric_limits<size_t>::max();
  }

  [[nodiscard]] inline uint64_t GetRsp() const override {
    return sigframe.GetRsp();
  }

  [[noreturn]] void JmpUnwindSysret(Thread &th) override;

  void MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) override;

  [[noreturn]] void JmpRestartSyscall() override;
  void ResetToSyscallStart() override {
    sigframe.uc.uc_mcontext.rip -= 2;
    sigframe.uc.uc_mcontext.rax = sigframe.uc.uc_mcontext.trapno;
  }

  [[noreturn]] void JmpUnwindPreemptEnable() override {
    assert_preempt_disabled();
    sigframe.InvalidateAltStack();
    sigframe.uc.mask = 0;
    nosave_switch_preempt_enable(
        reinterpret_cast<thread_fn_t>(GetUnwinderFunction()),
        reinterpret_cast<uintptr_t>(&sigframe.uc), 0);
  }

  [[noreturn]] void JmpUnwind() {
    sigframe.InvalidateAltStack();
    sigframe.uc.mask = 0;
    nosave_switch(reinterpret_cast<thread_fn_t>(GetUnwinderFunction()),
                  reinterpret_cast<uintptr_t>(&sigframe.uc), 0);
  }

  inline void MakeUnwinder(thread_tf &unwind_tf) const {
    unwind_tf.rsp = reinterpret_cast<uintptr_t>(&sigframe.uc);
    unwind_tf.rip = GetUnwinderFunction();
  }

  void DoSave(cereal::BinaryOutputArchive &ar) const override {
    ar(SigframeType::kKernelSignal);
    sigframe.DoSave(ar);
  }

  static KernelSignalTf *DoLoad(cereal::BinaryInputArchive &ar, uint64_t *rsp) {
    KernelSignalTf *tf = AllocateOnStack<KernelSignalTf>(rsp);
    k_sigframe *frame = k_sigframe::DoLoad(ar, rsp);
    new (tf) KernelSignalTf(frame);
    return tf;
  }

 private:
  inline uint64_t GetUnwinderFunction() const {
    if (!uintr_enabled)
      return reinterpret_cast<uintptr_t>(syscall_rt_sigreturn);

    return reinterpret_cast<uintptr_t>(__kframe_unwind_uiret);
  }

  k_sigframe &sigframe;
};

// Wrapper around thread_tfs that are set up during a function call-based
// system call.
class FunctionCallTf : public SyscallFrame {
 public:
  FunctionCallTf(thread_tf *tf) : tf(tf) {}
  FunctionCallTf(thread_tf &tf) : tf(&tf) {}
  FunctionCallTf() = default;

  // Allocate a new function call frame on the syscall stack. The caller must
  // ensure that the syscall stack was not already in use.
  static FunctionCallTf &CreateOnSyscallStack(Thread &th);

  void ReplaceTf(thread_tf *new_tf) { tf = new_tf; }

  void CopyRegs(thread_tf &dest_tf) const override;

  [[nodiscard]] inline thread_tf &GetFrame() { return *tf; }

  [[nodiscard]] inline uint64_t GetRsp() const override { return tf->rsp; }

  void MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) override;

  [[noreturn]] void JmpUnwindSysret(Thread &th) override;

  [[noreturn]] void JmpRestartSyscall() override;
  void ResetToSyscallStart() override;
  void ResetRestartRax() override;

  void ClearSyscallNr() override {
    tf->orig_rax = std::numeric_limits<size_t>::max();
  }

  [[nodiscard]] bool is_from_syscall() const override {
    return static_cast<size_t>(tf->orig_rax) < 4096;
  }

  void SetRax(uint64_t rax, std::optional<uint64_t> rsp) override {
    tf->rax = rax;
    if (rsp) tf->rsp = *rsp;
  }

  [[noreturn]] void JmpUnwindPreemptEnable() override {
    assert_preempt_disabled();
    __restore_tf_full_and_preempt_enable(tf);
    std::unreachable();
  }

  [[noreturn]] void JmpUnwindSysretPreemptEnable(Thread &th);

  FunctionCallTf &CloneTo(uint64_t *rsp) const override {
    FunctionCallTf *stack_wrapper = AllocateOnStack<FunctionCallTf>(rsp);
    thread_tf *stack_tf = PushToStack(rsp, *tf);
    new (stack_wrapper) FunctionCallTf(stack_tf);
    return *stack_wrapper;
  }

  JunctionSigframe &CloneSigframe(uint64_t *rsp) const override {
    thread_tf *stack_tf = PushToStack(rsp, *tf);
    JunctionSigframe *jframe = AllocateOnStack<JunctionSigframe>(rsp);
    jframe->type = SigframeType::kJunctionTf;
    jframe->tf = stack_tf;
    jframe->magic = kJunctionFrameMagic;
    return *jframe;
  }

  void DoSave(cereal::BinaryOutputArchive &ar) const override {
    ar(SigframeType::kJunctionTf);
    ar(*tf);
  }

  static FunctionCallTf *DoLoad(cereal::BinaryInputArchive &ar, uint64_t *rsp) {
    FunctionCallTf *fncall_tf = AllocateOnStack<FunctionCallTf>(rsp);
    thread_tf *tf = AllocateOnStack<thread_tf>(rsp);
    ar(*tf);
    new (fncall_tf) FunctionCallTf(tf);
    return fncall_tf;
  }

 private:
  inline uint64_t GetSysretUnwinderFunction() const {
    if (uintr_enabled)
      return reinterpret_cast<uint64_t>(__fncall_return_exit_loop_uintr);

    return reinterpret_cast<uint64_t>(__fncall_return_exit_loop);
  }

  thread_tf *tf;
};

// Wrapper around UINTR frames.
class UintrTf : public Trapframe {
 public:
  UintrTf(u_sigframe &sigframe) : sigframe(sigframe) {}
  UintrTf(u_sigframe *sigframe) : sigframe(*sigframe) {}

  // Unlike kernel signal-based interrupts, UIPI-based interrupts don't need to
  // check if a thread has left the kernel but is still on the syscall stack
  // because it uses the CLUI/UIRET instructions to block interrupts during this
  // period.
  constexpr static bool HasStackSwitchRace() { return false; }

  // Returns a reference to the underlying sigframe.
  [[nodiscard]] inline u_sigframe &GetFrame() { return sigframe; }

  [[noreturn]] void JmpUnwindPreemptEnable() override {
    assert_preempt_disabled();
    uint64_t rdi = reinterpret_cast<uint64_t>(&sigframe);
    uint64_t rsp = AlignDown(rdi, 16) - 8;
    nosave_switch_preempt_enable(
        reinterpret_cast<thread_fn_t>(UintrFullRestore), rsp, rdi);
  }

  [[noreturn]] void JmpUnwindSysret(Thread &th) override;

  inline void MakeUnwinder(thread_tf &unwind_tf) const {
    unwind_tf.rdi = reinterpret_cast<uint64_t>(&sigframe);
    unwind_tf.rsp = AlignDown(unwind_tf.rdi, 16) - 8;
    unwind_tf.rip = reinterpret_cast<uint64_t>(UintrFullRestore);
  }

  void MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) override;

  [[nodiscard]] inline uint64_t GetRsp() const override {
    return sigframe.GetRsp();
  }

  UintrTf &CloneTo(uint64_t *rsp) const override {
    UintrTf *stack_wrapper = AllocateOnStack<UintrTf>(rsp);
    u_sigframe *stack_tf = sigframe.CopyToStack(rsp);
    new (stack_wrapper) UintrTf(stack_tf);
    return *stack_wrapper;
  }

  JunctionSigframe &CloneSigframe(uint64_t *rsp) const override {
    u_sigframe *stack_tf = sigframe.CopyToStack(rsp);
    JunctionSigframe *jframe = AllocateOnStack<JunctionSigframe>(rsp);
    jframe->type = SigframeType::kJunctionUIPI;
    jframe->tf = stack_tf;
    jframe->magic = kJunctionFrameMagic;
    return *jframe;
  }

  void DoSave(cereal::BinaryOutputArchive &ar) const override {
    ar(SigframeType::kJunctionUIPI);
    sigframe.DoSave(ar);
  }

  static UintrTf *DoLoad(cereal::BinaryInputArchive &ar, uint64_t *rsp) {
    UintrTf *tf = AllocateOnStack<UintrTf>(rsp);
    u_sigframe *frame = u_sigframe::DoLoad(ar, rsp);
    new (tf) UintrTf(frame);
    return tf;
  }

 private:
  u_sigframe &sigframe;
};

inline void JunctionSigframe::Unwind() {
  switch (type) {
    case SigframeType::kKernelSignal:
      KernelSignalTf(reinterpret_cast<k_sigframe *>(tf))
          .JmpUnwindPreemptEnable();
    case SigframeType::kJunctionUIPI:
      UintrTf(reinterpret_cast<u_sigframe *>(tf)).JmpUnwindPreemptEnable();
    case SigframeType::kJunctionTf:
      FunctionCallTf(reinterpret_cast<thread_tf *>(tf))
          .JmpUnwindPreemptEnable();
    default:
      BUG();
  }
}

void LoadTrapframe(cereal::BinaryInputArchive &ar, Thread *th);

static_assert(sizeof(JunctionSigframe) % 16 == 0);

}  // namespace junction
