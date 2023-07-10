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
inline void usyscall_on_enter() { mythread().EnterSyscall(); }

inline void usyscall_on_exit() { mythread().ExitSyscall(); }

// Update in entry.S if changed.
static_assert(offsetof(thread, junction_tf) == JUNCTION_TF_OFF);
static_assert(offsetof(thread, syscallstack) == JUNCTION_STACK_OFFSET);
static_assert(sizeof(struct stack) == JUNCTION_STACK_SIZE);

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
}

}  // namespace junction
