// syscall.h - support for virtual syscalls.

#pragma once

#include "junction/base/error.h"
#include "junction/bindings/stack.h"
#include "junction/bindings/thread.h"
#include "junction/kernel/sigframe.h"
#include "junction/syscall/entry.h"

extern "C" {
#include "lib/caladan/runtime/defs.h"
}

namespace junction {

Status<void> SyscallInit();
void SyscallForceStackSwitch();
void SyscallRestoreNoStackSwitch();

// Update in entry.S if changed.
static_assert(offsetof(thread, stack) == JUNCTION_STACK_OFFSET);
static_assert(sizeof(struct stack) == JUNCTION_STACK_SIZE);
static_assert(JUNCTION_STACK_RESERVED == XSAVE_AREA_SIZE);
static_assert(offsetof(thread, entry_regs) == JUNCTION_TF_PTR_OFF);
static_assert(offsetof(thread, in_syscall) == JUNCTION_IN_SYSCALL_OFF);
static_assert(offsetof(thread, interrupt_state) == JUNCTION_INT_STATE_OFF);
static_assert(offsetof(thread, tf) == CALADAN_TF_OFF);
static_assert(offsetof(k_ucontext, uc_mcontext.rax) == SIGFRAME_RAX_OFFSET);
static_assert(offsetof(k_ucontext, uc_mcontext) == SIGFRAME_SIGCONTEXT);

static_assert(offsetof(sigcontext, r8) == SIGCONTEXT_R8);
static_assert(offsetof(sigcontext, r9) == SIGCONTEXT_R9);
static_assert(offsetof(sigcontext, r10) == SIGCONTEXT_R10);
static_assert(offsetof(sigcontext, r11) == SIGCONTEXT_R11);
static_assert(offsetof(sigcontext, r12) == SIGCONTEXT_R12);
static_assert(offsetof(sigcontext, r13) == SIGCONTEXT_R13);
static_assert(offsetof(sigcontext, r14) == SIGCONTEXT_R14);
static_assert(offsetof(sigcontext, r15) == SIGCONTEXT_R15);
static_assert(offsetof(sigcontext, rdi) == SIGCONTEXT_RDI);
static_assert(offsetof(sigcontext, rsi) == SIGCONTEXT_RSI);
static_assert(offsetof(sigcontext, rbp) == SIGCONTEXT_RBP);
static_assert(offsetof(sigcontext, rbx) == SIGCONTEXT_RBX);
static_assert(offsetof(sigcontext, rdx) == SIGCONTEXT_RDX);
static_assert(offsetof(sigcontext, rax) == SIGCONTEXT_RAX);
static_assert(offsetof(sigcontext, rcx) == SIGCONTEXT_RCX);
static_assert(offsetof(sigcontext, rip) == SIGCONTEXT_RIP);
static_assert(offsetof(sigcontext, rsp) == SIGCONTEXT_RSP);
static_assert(offsetof(sigcontext, eflags) == SIGCONTEXT_EFLAGS);
static_assert(offsetof(sigcontext, fpstate) == SIGCONTEXT_XSTATE);

// Changing members or layout of thread_tf may break assembly code in entry.S
static_assert(sizeof(thread_tf) == 168);

unsigned long sys_dispatch(long arg0, long arg1, long arg2, long arg3,
                           long arg4, long arg5, long syscall);

enum class FaultStatus : int {
  kNotInSyscall,  // Fault is not in a syscall target (it is in user code).
  kInSyscall,     // Fault occured while target is in syscall (or about to enter
                  // it).
  kCompletingSyscall,  // Fault occured after a syscall has completed but kernel
                       // text/stack are still in use.
};

__noinline FaultStatus CheckFaultIP(uintptr_t rip);

extern "C" {

// Declare a function that enters/exits the junction kernel. Any function that
// internally manipulates the in_kernel flag must be declared here. This
// function must also be included in the array of targets in syscall.cc.
#define SYSENTRY_ASM(name)             \
  extern const char name##_postcall[]; \
  extern const char name##_end[];      \
  long name

// Restart a system call, used when a signal interrupts a system call but the
// signal is ignored.
void __jmp_syscall_restart_nosave(struct thread_tf *tf) __noreturn;

// System call entry point for applications that require syscalls to run on an
// alternate stack (ie Golang).
SYSENTRY_ASM(junction_fncall_stackswitch_enter)
(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long sys_nr);

// System call entry point for clone/vfork for applications that require
// syscalls to run on an alternate stack (ie Golang).
SYSENTRY_ASM(junction_fncall_stackswitch_enter_preserve_regs)
(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long sys_nr);

// System call entry point for most applications.
SYSENTRY_ASM(junction_fncall_enter)
(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long sys_nr);

// System call entry point for clone/vfork for most applications.
SYSENTRY_ASM(junction_fncall_enter_preserve_regs)
(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long sys_nr);

// Return function for system calls that are delivered by trap. Ultimately jumps
// into __kframe_unwind_loop.
void __syscall_trap_return();

// Unwind a kernel signal frame on the system call stack. Checks for pending
// signals before fully unwinding the frame. Useable whether or not UINTR is
// enabled.
SYSENTRY_ASM(__kframe_unwind_loop)(uint64_t rax);

// Immediately restore a kernel signal frame using uiret.
void __kframe_unwind_uiret();

// Unwind a function call frame. Checks for pending signals before fully
// unwinding the frame.
SYSENTRY_ASM(__fncall_return_exit_loop)();

// Entry point for usys_rt_sigreturn, switches stacks and jumps to
// usys_rt_sigreturn with the sigframe as an argument.
SYSENTRY_ASM(usys_rt_sigreturn)() __noreturn;

// Switches stacks and calls new function with 3 argument registers, enabling
// preemption.
void __switch_and_preempt_enable(struct thread_tf *tf) __noreturn;

// Switches stacks and calls new function with 3 argument registers, enabling
// interrupts.
void __switch_and_interrupt_enable(struct thread_tf *tf) __noreturn;

// Same as __switch_and_preempt_enable, but also restores callee-saved
// registers, RAX, R10, and six standard argument registers.
void __restore_tf_full_and_preempt_enable(struct thread_tf *tf);
}

}  // namespace junction
