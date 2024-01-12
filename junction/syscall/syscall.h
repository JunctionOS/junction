// syscall.hpp - support for virtual syscalls.

#include "junction/base/error.h"
#include "junction/bindings/thread.h"
#include "junction/kernel/sigframe.h"
#include "junction/syscall/entry.h"

extern "C" {
#include "lib/caladan/runtime/defs.h"
}

namespace junction {

Status<void> SyscallInit();

// Update in entry.S if changed.
static_assert(offsetof(thread, stack) == JUNCTION_STACK_OFFSET);
static_assert(sizeof(struct stack) == JUNCTION_STACK_SIZE);
static_assert(offsetof(thread, entry_regs) == JUNCTION_TF_PTR_OFF);
static_assert(offsetof(thread, in_syscall) == JUNCTION_IN_SYSCALL_OFF);
static_assert(offsetof(thread, interrupt_state) == JUNCTION_INT_STATE_OFF);
static_assert(offsetof(thread, tf) == CALADAN_TF_OFF);
static_assert(offsetof(k_ucontext, uc_mcontext.rax) == SIGFRAME_RAX_OFFSET);
static_assert(offsetof(k_ucontext, uc_mcontext.rip) == SIGFRAME_RIP_OFFSET);
static_assert(offsetof(k_ucontext, uc_mcontext.rsp) == SIGFRAME_RSP_OFFSET);
static_assert(offsetof(k_ucontext, uc_mcontext.eflags) ==
              SIGFRAME_RFLAGS_OFFSET);

// Changing members or layout of thread_tf may break assembly code in entry.S
static_assert(sizeof(thread_tf) == 152);

unsigned long sys_dispatch(long arg0, long arg1, long arg2, long arg3,
                           long arg4, long arg5, long syscall);

extern "C" {

// Entry point for new threads spawned with clone; restores general purpose
// registers not restored by Caladan's thread scheduler, zeros %rax, and starts
// the thread.
void clone_fast_start(void *rip) __noreturn;

// Restart a system call, used when a signal interrupts a system call but the
// signal is ignored.
void __jmp_syscall_restart_nosave(struct thread_tf *tf) __noreturn;

// System call entry point for applications that require syscalls to run on an
// alternate stack (ie Golang).
long junction_fncall_stackswitch_enter(long arg0, long arg1, long arg2,
                                       long arg3, long arg4, long arg5,
                                       long sys_nr);

// System call entry point for applications that require syscalls to run on an
// alternate stack (ie Golang). This variant used when UINTR is enabled.
long junction_fncall_stackswitch_enter_uintr(long arg0, long arg1, long arg2,
                                             long arg3, long arg4, long arg5,
                                             long sys_nr);

// System call entry point for clone/vfork for applications that require
// syscalls to run on an alternate stack (ie Golang).
long junction_fncall_stackswitch_enter_preserve_regs(long arg0, long arg1,
                                                     long arg2, long arg3,
                                                     long arg4, long arg5,
                                                     long sys_nr);

// System call entry point for clone/vfork for applications that require
// syscalls to run on an alternate stack (ie Golang). This variant used when
// UINTR is enabled.
long junction_fncall_stackswitch_enter_preserve_regs_uintr(long arg0, long arg1,
                                                           long arg2, long arg3,
                                                           long arg4, long arg5,
                                                           long sys_nr);

// System call entry point for most applications.
long junction_fncall_enter(long arg0, long arg1, long arg2, long arg3,
                           long arg4, long arg5, long sys_nr);

// System call entry point for clone/vfork for most applications.
long junction_fncall_enter_preserve_regs(long arg0, long arg1, long arg2,
                                         long arg3, long arg4, long arg5,
                                         long sys_nr);

// Return function for system calls that are delivered by trap.
void __syscall_trap_return();

// Unwind a kernel signal frame on the system call stack. Checks for pending
// signals before fully unwinding the frame.
void __kframe_unwind_loop(uint64_t rax);

// Variant of __syscall_trap_return for UINTR.
void __syscall_trap_return_uintr();

// Unwind a kernel signal frame on the system call stack. Checks for pending
// signals before fully unwinding the frame. This variant must be used when
// UINTR is enabled.
void __kframe_unwind_loop_uintr(uint64_t rax);

// Unwind a function call frame. Checks for pending signals before fully
// unwinding the frame.
void __fncall_return_exit_loop();

// Unwind a function call frame. Checks for pending signals before fully
// unwinding the frame. This variant must be used when UINTR is enabled.
void __fncall_return_exit_loop_uintr();

// Entry point for usys_rt_sigreturn, switches stacks and jumps to
// usys_rt_sigreturn with the sigframe as an argument.
void usys_rt_sigreturn_enter() __noreturn;

// Switches stacks and calls new function with 3 argument registers, enabling
// preemption.
void __switch_and_preempt_enable(struct thread_tf *tf) __noreturn;

// Switches stacks and calls new function with 3 argument registers, enabling
// preemption.
void __switch_and_interrupt_enable(struct thread_tf *tf) __noreturn;

// Same as __switch_and_preempt_enable, but also restores callee-saved
// registers, RAX, R10, and six standard argument registers.
void __restore_tf_full_and_preempt_enable(struct thread_tf *tf);
}

}  // namespace junction
