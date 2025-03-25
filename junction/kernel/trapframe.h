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
class Trapframe;

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

  Trapframe &CloneTo(uint64_t *rsp);
};

class Thread;

class Trapframe {
 public:
  // Get the RSP from this trapframe.
  [[nodiscard]] virtual uint64_t GetRsp() const = 0;
  [[nodiscard]] virtual uint64_t GetRip() const = 0;
  virtual void SetRip(uint64_t ip) = 0;

  // Copy this trapframe to a new stack, returns a reference to the new
  // instance.
  virtual Trapframe &CloneTo(uint64_t *rsp) const = 0;

  // Clone this trapframe onto a signal handler stack with a Sigframe to unwind
  // it.
  virtual JunctionSigframe &CloneSigframe(uint64_t *rsp) const = 0;

  // Immediately restores this trapframe, exiting the Junction kernel and
  // checking for signals. Expects preemption to be enabled.
  [[noreturn]] virtual void JmpUnwindSysret(Thread &th) = 0;

  // Set up @unwind_tf to unwind this trapframe after performing a final check
  // for pending signals. Unwinders here cannot assume that the frame is a
  // system call and therefore must not pass a non-zero argument to RunSignals.
  // This trapframe instance is attached to @th and must reside on the syscall
  // stack.
  virtual void MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) = 0;

  virtual void DoSave(cereal::BinaryOutputArchive &ar, int rax) const = 0;
};

// Trapframes that are created via system call entry to the Junction kernel.
class SyscallFrame : virtual public Trapframe {
 public:
  // Immediately restart this system call.
  [[noreturn]] virtual void JmpRestartSyscall() = 0;

  // Modify the trapframe to repeat the system call when restored.
  virtual void ResetToSyscallStart() = 0;

  // Set the value for RAX in this trapframe.
  virtual void SetRax(uint64_t rax,
                      std::optional<uint64_t> rsp = std::nullopt) = 0;

  virtual SyscallFrame &CloneTo(uint64_t *rsp) const override = 0;

  [[nodiscard]] virtual uint64_t GetOrigRax() const = 0;
};

// Kernel signals are used both for interrupts and to trap syscall instructions.
class KernelSignalTf final : public SyscallFrame {
 public:
  KernelSignalTf(k_sigframe &sigframe) : sigframe(sigframe) {}
  KernelSignalTf(k_sigframe *sigframe) : sigframe(*sigframe) {}
  KernelSignalTf(k_ucontext *uc) : sigframe(*k_sigframe::FromUcontext(uc)) {}
  KernelSignalTf(const KernelSignalTf &tf) : sigframe(tf.sigframe) {}

  // Returns a reference to the underlying sigframe.
  [[nodiscard]] inline k_sigframe &GetFrame() { return sigframe; }
  [[nodiscard]] inline const k_sigframe &GetFrame() const { return sigframe; }

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

  void SetRip(uint64_t ip) override { sigframe.uc.uc_mcontext.rip = ip; }

  [[nodiscard]] uint64_t GetOrigRax() const override {
    return sigframe.uc.uc_mcontext.trapno;
  }

  [[nodiscard]] inline uint64_t GetRsp() const override {
    return sigframe.GetRsp();
  }

  [[nodiscard]] inline uint64_t GetRip() const override {
    return sigframe.GetRip();
  }

  [[nodiscard]] inline uint64_t GetFaultAddr() const {
    return reinterpret_cast<uint64_t>(GetFrame().info.si_addr);
  }

  [[noreturn]] void JmpUnwindSysret(Thread &th) override;

  void MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) override;

  [[noreturn]] void JmpRestartSyscall() override;
  void ResetToSyscallStart() override {
    sigframe.uc.uc_mcontext.rip -= 2;
    sigframe.uc.uc_mcontext.rax = sigframe.uc.uc_mcontext.trapno;
  }

  [[noreturn]] void JmpUnwind() {
    sigframe.uc.mask = 0;
    nosave_switch(reinterpret_cast<thread_fn_t>(GetUnwinderFunction()),
                  reinterpret_cast<uintptr_t>(&sigframe.uc), 0);
  }

  inline void MakeUnwinder(thread_tf &unwind_tf) const {
    unwind_tf.rsp = reinterpret_cast<uintptr_t>(&sigframe.uc);
    unwind_tf.rip = GetUnwinderFunction();
  }

  void DoSave(cereal::BinaryOutputArchive &ar, int rax) const override;

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

inline void InitializeThreadTf(thread_tf &tf) {
  tf.rflags = 0;
  tf.xsave_area = nullptr;
}

// Wrapper around thread_tfs that are set up during a function call-based
// system call.
class FunctionCallTf final : public SyscallFrame {
 public:
  FunctionCallTf(thread_tf *tf) : tf(tf) {}
  FunctionCallTf(thread_tf &tf) : tf(&tf) {}
  FunctionCallTf() = default;

  // Allocate a new function call frame on the syscall stack. The caller must
  // ensure that the syscall stack was not already in use.
  static FunctionCallTf &CreateOnSyscallStack(Thread &th);

  void ReplaceTf(thread_tf *new_tf) { tf = new_tf; }

  [[nodiscard]] inline thread_tf &GetFrame() { return *tf; }

  [[nodiscard]] inline uint64_t GetRsp() const override { return tf->rsp; }
  [[nodiscard]] inline uint64_t GetRip() const override { return tf->rip; }

  void MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) override;

  [[noreturn]] void JmpUnwindSysret(Thread &th) override;

  [[noreturn]] void JmpRestartSyscall() override;
  void ResetToSyscallStart() override;

  void SetRax(uint64_t rax, std::optional<uint64_t> rsp) override {
    tf->rax = rax;
    if (rsp) tf->rsp = *rsp;
  }

  void SetRip(uint64_t ip) override { tf->rip = ip; }

  [[nodiscard]] uint64_t GetOrigRax() const override final {
    return tf->orig_rax;
  }

  [[noreturn]] void JmpUnwindSysretPreemptEnable(Thread &th);

  FunctionCallTf &CloneTo(uint64_t *rsp) const override {
    FunctionCallTf *stack_wrapper = AllocateOnStack<FunctionCallTf>(rsp);
    thread_tf *stack_tf = CopyRawToStack(rsp);
    new (stack_wrapper) FunctionCallTf(stack_tf);
    return *stack_wrapper;
  }

  JunctionSigframe &CloneSigframe(uint64_t *rsp) const override {
    thread_tf *stack_tf = CopyRawToStack(rsp);
    JunctionSigframe *jframe = AllocateOnStack<JunctionSigframe>(rsp);
    jframe->type = SigframeType::kJunctionTf;
    jframe->tf = stack_tf;
    jframe->magic = kJunctionFrameMagic;
    return *jframe;
  }

  void DoSave(cereal::BinaryOutputArchive &ar, int rax) const override;

  static FunctionCallTf *DoLoad(cereal::BinaryInputArchive &ar, uint64_t *rsp) {
    FunctionCallTf *fncall_tf = AllocateOnStack<FunctionCallTf>(rsp);

    size_t xlen;
    unsigned char *new_xarea = nullptr;
    ar(xlen);
    if (xlen) {
      *rsp = AlignDown(*rsp - xlen, kXsaveAlignment);
      new_xarea = reinterpret_cast<unsigned char *>(*rsp);
      ar(cereal::binary_data(new_xarea, xlen));
    }

    thread_tf *tf = AllocateOnStack<thread_tf>(rsp);
    ar(*tf);
    tf->xsave_area = new_xarea;
    new (fncall_tf) FunctionCallTf(tf);
    return fncall_tf;
  }

 private:
  inline uint64_t GetSysretUnwinderFunction() const {
    return reinterpret_cast<uint64_t>(__fncall_return_exit_loop);
  }

  thread_tf *CopyRawToStack(uint64_t *rsp) const {
    unsigned char *new_xarea = nullptr;

    if (tf->xsave_area) {
      size_t len = GetXsaveAreaSize(reinterpret_cast<xstate *>(tf->xsave_area));
      *rsp = AlignDown(*rsp - len, kXsaveAlignment);
      new_xarea = reinterpret_cast<unsigned char *>(*rsp);
      std::memcpy(new_xarea, tf->xsave_area, len);
    }

    thread_tf *stack_tf = PushToStack(rsp, *tf);
    stack_tf->xsave_area = new_xarea;
    return stack_tf;
  }

  thread_tf *tf;
};

// Wrapper around UINTR frames.
class UintrTf final : public Trapframe {
 public:
  UintrTf(u_sigframe &sigframe) : sigframe(sigframe) {}
  UintrTf(u_sigframe *sigframe) : sigframe(*sigframe) {}

  // Returns a reference to the underlying sigframe.
  [[nodiscard]] inline u_sigframe &GetFrame() { return sigframe; }

  [[noreturn]] void JmpUnwindSysret(Thread &th) override;

  inline void MakeUnwinder(thread_tf &unwind_tf) const {
    unwind_tf.rdi = reinterpret_cast<uint64_t>(&sigframe);
    unwind_tf.rsp = AlignForFunctionEntry(unwind_tf.rdi);
    unwind_tf.rip = reinterpret_cast<uint64_t>(UintrFullRestore);
  }

  void MakeUnwinderSysret(Thread &th, thread_tf &unwind_tf) override;

  [[nodiscard]] inline uint64_t GetRsp() const override {
    return sigframe.GetRsp();
  }

  [[nodiscard]] inline uint64_t GetRip() const override {
    return sigframe.GetRip();
  }

  void SetRip(uint64_t ip) override { sigframe.rip = ip; }

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

  void DoSave(cereal::BinaryOutputArchive &ar, int rax) const override;

  static UintrTf *DoLoad(cereal::BinaryInputArchive &ar, uint64_t *rsp) {
    UintrTf *tf = AllocateOnStack<UintrTf>(rsp);
    u_sigframe *frame = u_sigframe::DoLoad(ar, rsp);
    new (tf) UintrTf(frame);
    return tf;
  }

 private:
  u_sigframe &sigframe;
};

void LoadTrapframe(cereal::BinaryInputArchive &ar, Thread *th);

static_assert(sizeof(JunctionSigframe) % kJunctionFrameAlign == 0);

}  // namespace junction
