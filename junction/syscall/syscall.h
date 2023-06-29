// syscall.hpp - support for virtual syscalls.

#include "junction/base/error.h"
#include "junction/bindings/thread.h"
#include "junction/syscall/entry.h"

extern "C" {
#include "lib/caladan/runtime/defs.h"
}

namespace junction {

Status<void> SyscallInit();

// Called every time a thread enters/exits a usyscall
inline void usyscall_on_enter() {}
inline void usyscall_on_exit() {}

// Update in entry.S if changed.
static_assert(offsetof(thread, junction_tf) == JUNCTION_TF_OFF);
static_assert(offsetof(thread, xsave_area) == JUNCTION_XSAVEPTR_OFF);
static_assert(offsetof(thread, syscallstack) == JUNCTION_STACK_OFFSET);
static_assert(sizeof(struct stack) == JUNCTION_STACK_SIZE);

unsigned long sys_dispatch(long arg0, long arg1, long arg2, long arg3,
                           long arg4, long arg5, long syscall);

// Assembly routines to assist with register saving/restoring for clone calls
extern "C" {
void clone_fast_start(void *rip) __noreturn;
unsigned long usys_clone3_enter(long arg0, long arg1, long arg2, long arg3,
                                long arg4, long arg5);
unsigned long usys_clone_enter(long arg0, long arg1, long arg2, long arg3,
                               long arg4, long arg5);
long junction_fncall_stackswitch_enter(long arg0, long arg1, long arg2,
                                       long arg3, long arg4, long arg5);
long junction_fncall_stackswitch_clone_enter(long arg0, long arg1, long arg2,
                                             long arg3, long arg4, long arg5);
void __junction_syscall_intercept();
void __junction_syscall_intercept_clone_ret() __noreturn;
}

}  // namespace junction
