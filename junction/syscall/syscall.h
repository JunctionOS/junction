// syscall.hpp - support for virtual syscalls.

#include "junction/base/error.h"
#include "junction/bindings/thread.h"
#include "junction/kernel/proc.h"
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

// Changing members or layout of thread_tf may break assembly code in entry.S
static_assert(sizeof(thread_tf) == 152);

unsigned long sys_dispatch(long arg0, long arg1, long arg2, long arg3,
                           long arg4, long arg5, long syscall);

// Assembly routines to assist with register saving/restoring for clone calls
extern "C" {
void clone_fast_start(void *rip) __noreturn;
void __syscall_restart_nosave(struct thread_tf *tf) __noreturn;

long junction_fncall_stackswitch_enter(long arg0, long arg1, long arg2,
                                       long arg3, long arg4, long arg5);
long junction_fncall_stackswitch_enter_preserve_regs(long arg0, long arg1,
                                                     long arg2, long arg3,
                                                     long arg4, long arg5);
long junction_fncall_enter_preserve_regs(long arg0, long arg1, long arg2,
                                         long arg3, long arg4, long arg5);
long junction_fncall_enter(long arg0, long arg1, long arg2, long arg3,
                           long arg4, long arg5);

void __syscall_trap_return();

void usys_rt_sigreturn_enter() __noreturn;

void __switch_and_preempt_enable(struct thread_tf *tf) __noreturn;
void __restore_tf_full_and_preempt_enable(struct thread_tf *tf);

void __nosave_switch(thread_fn_t fn, uint64_t stack, uint64_t arg0) __noreturn;
}

}  // namespace junction
