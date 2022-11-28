// syscall.hpp - support for virtual syscalls.

#include "junction/base/error.h"

namespace junction {

Status<void> SyscallInit();

unsigned long sys_dispatch(long arg0, long arg1, long arg2, long arg3,
                           long arg4, long arg5, long syscall);

}  // namespace junction
