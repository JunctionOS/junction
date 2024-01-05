
#include "junction/syscall/syscall.h"

#include <cstring>

#include "junction/junction.h"
#include "junction/syscall/systbl.h"

namespace junction {

Status<void> SyscallInit() {
  sysfn_t *dst_tbl = reinterpret_cast<sysfn_t *>(SYSTBL_TRAMPOLINE_LOC);

  if (uintr_enabled) {
    sys_tbl_strace[451] = sys_tbl[451] =
        reinterpret_cast<sysfn_t>(junction_fncall_stackswitch_enter_uintr);
    sys_tbl_strace[452] = sys_tbl[452] = reinterpret_cast<sysfn_t>(
        junction_fncall_stackswitch_enter_preserve_regs_uintr);
  }

  Status<void> ret =
      KernelMMapFixed(dst_tbl, sizeof(sys_tbl), PROT_READ | PROT_WRITE, 0);
  if (unlikely(!ret)) return ret;

  if (GetCfg().strace_enabled())
    std::memcpy(sys_tbl, sys_tbl_strace, sizeof(sys_tbl_strace));

  if (GetCfg().stack_switch_enabled()) {
    sys_tbl[453] = sys_tbl[451];
    sys_tbl[454] = sys_tbl[452];
  }

  std::memcpy(dst_tbl, sys_tbl, sizeof(sys_tbl));

  return {};
}

// this function is only used for system calls that are trapped
unsigned long sys_dispatch(long arg0, long arg1, long arg2, long arg3,
                           long arg4, long arg5, long syscall) {
  if (unlikely(syscall >= SYS_NR)) return -ENOSYS;

  return sys_tbl[syscall](arg0, arg1, arg2, arg3, arg4, arg5);
}

}  // namespace junction
