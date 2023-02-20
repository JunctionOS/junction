// syscall.hpp - support for virtual syscalls.

#include "junction/base/error.h"
#include "junction/bindings/thread.h"
#include "junction/syscall/entry.h"

namespace junction {

Status<void> SyscallInit();

// Update in entry.S if changed.
static_assert(offsetof(thread, junction_tf) == JUNCTION_TF_OFF);
static_assert(offsetof(thread, xsave_area) == JUNCTION_XSAVEPTR_OFF);
static_assert(offsetof(thread, stack) == JUNCTION_STACK_OFFSET);

unsigned long sys_dispatch(long arg0, long arg1, long arg2, long arg3,
                           long arg4, long arg5, long syscall);

// Assembly routines to assist with register saving/restoring for clone calls
extern "C" {
void clone_fast_start(void *rip) __noreturn;
unsigned long usys_clone3_enter(long arg0, long arg1, long arg2, long arg3,
                                long arg4, long arg5);
unsigned long usys_clone_enter(long arg0, long arg1, long arg2, long arg3,
                               long arg4, long arg5);
void junction_syscall_full_trap();
void junction_full_restore_newth(uint64_t rsp) __noreturn;
}

}  // namespace junction
