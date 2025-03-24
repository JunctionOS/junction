
#include "junction/syscall/syscall.h"

#include <cstring>

#include "junction/junction.h"
#include "junction/kernel/mm.h"
#include "junction/syscall/systbl.h"
#include "junction/syscall/vdso.h"

namespace junction {

struct SyscallTarget {
  uintptr_t start;
  uintptr_t postcall;
  uintptr_t end;
};

#define DECLARE_TARGET(name)                          \
  {                                                   \
    reinterpret_cast<uintptr_t>(name),                \
        reinterpret_cast<uintptr_t>(name##_postcall), \
        reinterpret_cast<uintptr_t>(name##_end)       \
  }

const std::array<SyscallTarget, 7> syscallTargets = {
    {DECLARE_TARGET(junction_fncall_enter),
     DECLARE_TARGET(junction_fncall_enter_preserve_regs),
     DECLARE_TARGET(junction_fncall_stackswitch_enter),
     DECLARE_TARGET(junction_fncall_stackswitch_enter_preserve_regs),
     DECLARE_TARGET(__kframe_unwind_loop),
     DECLARE_TARGET(__fncall_return_exit_loop),
     DECLARE_TARGET(usys_rt_sigreturn)}};

// Determines if an IP is in a Junction function (potentially before or after
// the syscall flag is set/cleared).
__noinline FaultStatus CheckFaultIP(uintptr_t rip) {
  for (const auto &target : syscallTargets) {
    if (rip >= target.start && rip < target.postcall)
      return FaultStatus::kInSyscall;
    else if (rip >= target.postcall && rip < target.end)
      return FaultStatus::kCompletingSyscall;
  }
  return FaultStatus::kNotInSyscall;
}

static sysfn_t *dst_tbl;

void SyscallForceStackSwitch() {
  dst_tbl[453] = sys_tbl[451];
  dst_tbl[454] = sys_tbl[452];
}

void SyscallRestoreNoStackSwitch() {
  dst_tbl[453] = sys_tbl[453];
  dst_tbl[454] = sys_tbl[454];
}

Status<void> SyscallInit() {
  dst_tbl = reinterpret_cast<sysfn_t *>(SYSTBL_TRAMPOLINE_LOC);

  Status<void> ret =
      KernelMMapFixed(dst_tbl, sizeof(sys_tbl), PROT_READ | PROT_WRITE, 0);
  if (unlikely(!ret)) return ret;

  MemoryMap::RegisterMMRegion(SYSTBL_TRAMPOLINE_LOC, sizeof(sys_tbl));

  if (GetCfg().strace_enabled())
    std::memcpy(sys_tbl, sys_tbl_strace, sizeof(sys_tbl_strace));

  if (GetCfg().stack_switch_enabled()) {
    sys_tbl[453] = sys_tbl[451];
    sys_tbl[454] = sys_tbl[452];
  }

  std::memcpy(dst_tbl, sys_tbl, sizeof(sys_tbl));

  // Move VDSO to a fixed location.
  void *mret = mremap(vdso_initial_location(), vdso_size(), vdso_size(),
                      MREMAP_MAYMOVE | MREMAP_FIXED,
                      reinterpret_cast<void *>(kVDSOLocation));
  if (mret == MAP_FAILED) return MakeError(-errno);

  MemoryMap::RegisterMMRegion(kVDSOLocation, vdso_size());
  return {};
}

// this function is only used for system calls that are trapped
unsigned long sys_dispatch(long arg0, long arg1, long arg2, long arg3,
                           long arg4, long arg5, long syscall) {
  if (unlikely(syscall >= SYS_NR)) return -ENOSYS;

  return sys_tbl[syscall](arg0, arg1, arg2, arg3, arg4, arg5);
}

}  // namespace junction
