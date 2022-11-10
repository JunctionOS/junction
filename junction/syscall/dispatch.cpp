#include "junction/syscall/dispatch.hpp"

#include <syscall.h>

#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"

namespace junction {

unsigned long sys_dispatch(long syscall, long arg0, long arg1, long arg2,
                           long arg3, long arg4, long arg5) {
  switch (syscall) {
    case SYS_getpid:
      return usys_getpid();
    default:
      return ksys_default(syscall, arg0, arg1, arg2, arg3, arg4, arg5);
  }
}

}  // namespace junction
