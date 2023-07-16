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

// Called every time a thread enters/exits a usyscall
inline void usyscall_on_enter() { mythread().OnSyscallEnter(); }

inline void usyscall_on_leave(long rax) { mythread().OnSyscallLeave(rax); }

// Update in entry.S if changed.
static_assert(offsetof(thread, junction_tf) == JUNCTION_TF_OFF);
static_assert(offsetof(thread, stack) == JUNCTION_STACK_OFFSET);
static_assert(sizeof(struct stack) == JUNCTION_STACK_SIZE);
static_assert(offsetof(thread, tlsvar) == THREAD_STRUCT_TVAR);
static_assert(static_cast<uint64_t>(ThreadState::kArmedAltstack) ==
              THREAD_STATE_ALTSTACK);

unsigned long sys_dispatch(long arg0, long arg1, long arg2, long arg3,
                           long arg4, long arg5, long syscall);

// Assembly routines to assist with register saving/restoring for clone calls
extern "C" {
void clone_fast_start(void *rip) __noreturn;
long junction_fncall_stackswitch_enter(long arg0, long arg1, long arg2,
                                       long arg3, long arg4, long arg5);
long junction_fncall_stackswitch_clone_enter(long arg0, long arg1, long arg2,
                                             long arg3, long arg4, long arg5);
void usys_rt_sigreturn_enter() __noreturn;

void __switch_and_preempt_enable(struct thread_tf *tf) __noreturn;
void __restore_tf_full_and_preempt_enable(struct thread_tf *tf);

void __nosave_switch(thread_fn_t fn, void *stack, uint64_t arg0) __noreturn;
void __save_tf_switch(struct thread_tf *tf, thread_fn_t fn, void *stack,
                      uint64_t arg0);
}

}  // namespace junction
