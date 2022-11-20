#include "junction/syscall/syscall.hpp"

#include <cstring>

#include "junction/kernel/ksys.h"
#include "junction/syscall/systbl.hpp"

namespace junction {

Status<void> SyscallInit() {
  Status<void> ret = KernelMMapFixed(SYSTBL_TRAMPOLINE_LOC, sizeof(sys_tbl),
                                     PROT_READ | PROT_WRITE, 0);
  if (unlikely(!ret)) return MakeError(ret);

  std::memcpy(SYSTBL_TRAMPOLINE_LOC, sys_tbl, sizeof(sys_tbl));
  return {};
}

// this function is only used for system calls that are trapped
unsigned long sys_dispatch(long arg0, long arg1, long arg2, long arg3,
                           long arg4, long arg5, long syscall) {
  if (syscall >= SYS_NR) return -1;

  return sys_tbl[syscall](arg0, arg1, arg2, arg3, arg4, arg5);
}

}  // namespace junction
