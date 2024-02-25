#pragma once

extern "C" {
#include <base/syscall.h>
}

#include "junction/base/arch.h"
#include "junction/bindings/stack.h"
#include "junction/bindings/thread.h"
#include "junction/kernel/sigframe.h"
#include "junction/syscall/syscall.h"

inline constexpr uint64_t kJunctionFrameMagic = 0x696e63656e64696fUL;
inline constexpr size_t kJunctionFrameAlign = 16;

namespace junction {

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

  // Immediately restores this trapframe.
  [[noreturn]] virtual void JmpUnwind() = 0;

  // Set up @unwind_tf to unwind this trapframe after performing a final check
  // for pending signals. Unwinders here cannot assume that the frame is a
  // system call and therefore must not pass a non-zero argument to RunSignals.
  virtual void MakeUnwinderSysret(thread_tf &unwind_tf) const = 0;
};

// Trapframes that are created via system call entry to the Junction kernel.
class SyscallFrame : virtual public Trapframe {
 public:
  // Immediately restart this system call.
  [[noreturn]] virtual void JmpRestartSyscall() = 0;

  // Modify the trapframe to repeat the system call when restored.
  virtual void ResetToSyscallStart() = 0;

  // Set the value for RAX in this trapframe.
  virtual void SetRax(uint64_t rax) = 0;

  // Copies registers to @dest_tf.
  virtual void CopyRegs(thread_tf &dest_tf) const = 0;
};

template <typename T>
concept InterruptFrame = requires(T t, thread_tf &tf) {
  { &t } -> std::convertible_to<Trapframe *>;
  { t.MakeUnwinder(tf) } -> std::same_as<void>;
  { T::HasStackSwitchRace() } -> std::same_as<bool>;
  { T::SwitchFromInterruptContext(tf) } -> std::same_as<void>;
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

  inline void MakeUnwinder(thread_tf &unwind_tf) const {
    unwind_tf.rsp = reinterpret_cast<uintptr_t>(&sigframe.uc);
    if (!uintr_enabled)
      unwind_tf.rip = reinterpret_cast<uintptr_t>(syscall_rt_sigreturn);
    else
      unwind_tf.rip = reinterpret_cast<uintptr_t>(__kframe_unwind_uiret);
  }

  // Push this instance to the stack in such a way that it can be directly
  // exposed to the user (JunctionFrame placed between the k_sigframe and
  // xstate).
  k_sigframe *PushUserVisibleFrame(uint64_t *rsp) const;

  void SetRax(uint64_t rax) override { sigframe.uc.uc_mcontext.rax = rax; }

  [[nodiscard]] inline uint64_t GetRsp() const override {
    return sigframe.GetRsp();
  }

  inline void MakeUnwinderSysret(thread_tf &unwind_tf) const override {
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

  [[noreturn]] void JmpRestartSyscall() override;
  void ResetToSyscallStart() override {
    sigframe.uc.uc_mcontext.rip -= 2;
    sigframe.uc.uc_mcontext.rax = sigframe.uc.uc_mcontext.trapno;
  }

  // Routine used to switch from a signal delivery context.
  [[noreturn]] static inline void SwitchFromInterruptContext(thread_tf &tf) {
    assert_preempt_disabled();
    __switch_and_preempt_enable(&tf);
  }

  [[noreturn]] void JmpUnwind() override {
    assert_preempt_disabled();
    sigframe.InvalidateAltStack();
    sigframe.uc.mask = 0;
    thread_tf tf;
    MakeUnwinder(tf);
    __switch_and_preempt_enable(&tf);
  }

 private:
  k_sigframe &sigframe;
};

// Wrapper around thread_tfs that are set up during a function call-based
// system call.
class FunctionCallTf : public SyscallFrame {
 public:
  FunctionCallTf(thread_tf *tf) : tf(tf) {}
  FunctionCallTf(thread_tf &tf) : tf(&tf) {}
  FunctionCallTf() = default;

  void CopyRegs(thread_tf &dest_tf) const override;

  [[nodiscard]] inline uint64_t GetRsp() const override { return tf->rsp; }

  inline void MakeUnwinderSysret(thread_tf &unwind_tf) const override {
    unwind_tf.rsp = reinterpret_cast<uint64_t>(tf);
    if (uintr_enabled) {
      unwind_tf.rip =
          reinterpret_cast<uint64_t>(__fncall_return_exit_loop_uintr);
    } else {
      unwind_tf.rip = reinterpret_cast<uint64_t>(__fncall_return_exit_loop);
    }
  }

  [[noreturn]] void JmpRestartSyscall() override;
  void ResetToSyscallStart() override;
  void SetRax(uint64_t rax) override { tf->rax = rax; }

  [[noreturn]] void JmpUnwind() override {
    assert_preempt_disabled();
    __restore_tf_full_and_preempt_enable(tf);
    std::unreachable();
  }

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

 private:
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

  [[noreturn]] void JmpUnwind() override {
    assert_preempt_disabled();
    thread_tf tf;
    MakeUnwinder(tf);
    __switch_and_preempt_enable(&tf);
  }

  inline void MakeUnwinder(thread_tf &unwind_tf) const {
    unwind_tf.rdi = reinterpret_cast<uint64_t>(&sigframe);
    unwind_tf.rsp = AlignDown(unwind_tf.rdi, 16) - 8;
    unwind_tf.rip = reinterpret_cast<uint64_t>(UintrFullRestore);
  }

  inline void MakeUnwinderSysret(thread_tf &unwind_tf) const override {
    unwind_tf.rdi = reinterpret_cast<uint64_t>(&sigframe);
    unwind_tf.rsp = AlignDown(unwind_tf.rdi, 16) - 8;
    unwind_tf.rip = reinterpret_cast<uint64_t>(UintrLoopReturn);
  }

  [[nodiscard]] inline uint64_t GetRsp() const override {
    return sigframe.GetRsp();
  }

  [[noreturn]] static inline void SwitchFromInterruptContext(thread_tf &tf) {
    assert(!TestUIF());
    __switch_and_interrupt_enable(&tf);
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

 private:
  u_sigframe &sigframe;
};

inline void JunctionSigframe::Unwind() {
  switch (type) {
    case SigframeType::kKernelSignal:
      KernelSignalTf(reinterpret_cast<k_sigframe *>(tf)).JmpUnwind();
    case SigframeType::kJunctionUIPI:
      UintrTf(reinterpret_cast<u_sigframe *>(tf)).JmpUnwind();
    case SigframeType::kJunctionTf:
      FunctionCallTf(reinterpret_cast<thread_tf *>(tf)).JmpUnwind();
    default:
      BUG();
  }
}

static_assert(sizeof(JunctionSigframe) % 16 == 0);

}  // namespace junction