#include "junction/syscall/syscall.h"

#include <cstring>
#include <iostream>

#include "junction/bindings/log.h"
#include "junction/kernel/ksys.h"
#include "junction/syscall/systbl.h"

extern "C" {
#include <dlfcn.h>
}

namespace junction {

void SetupVdsoFunction(void *vdso, int sysnr, const char *fname) {
  void *fptr = dlsym(vdso, fname);
  if (unlikely(!fptr)) {
    std::cerr << "Unable to resolve vDSO for " << fname << std::endl;
    return;
  }

  // Set trampoline table pointer directly to vdso function
  sys_tbl[sysnr] = reinterpret_cast<sysfn_t>(fptr);
}

Status<void> InitVdso() {
  void *vdso = dlopen("linux-vdso.so.1", RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);

  if (!vdso) {
    std::cerr << "Unable to intialize vdso: " << dlerror() << std::endl;
    return MakeError(1);
  }

  SetupVdsoFunction(vdso, __NR_gettimeofday, "__vdso_gettimeofday");
  SetupVdsoFunction(vdso, __NR_clock_getres, "__vdso_clock_getres");
  SetupVdsoFunction(vdso, __NR_clock_gettime, "__vdso_clock_gettime");
  SetupVdsoFunction(vdso, __NR_time, "__vdso_time");

  return {};
}

Status<void> SyscallInit() {
  Status<void> ret = KernelMMapFixed(SYSTBL_TRAMPOLINE_LOC, sizeof(sys_tbl),
                                     PROT_READ | PROT_WRITE, 0);
  if (unlikely(!ret)) return ret;

  ret = InitVdso();
  if (unlikely(!ret)) return ret;

  std::memcpy(SYSTBL_TRAMPOLINE_LOC, sys_tbl, sizeof(sys_tbl));
  return {};
}

// this function is only used for system calls that are trapped
unsigned long sys_dispatch(long arg0, long arg1, long arg2, long arg3,
                           long arg4, long arg5, long syscall) {
  if (unlikely(syscall >= SYS_NR)) return -ENOSYS;

  return sys_tbl[syscall](arg0, arg1, arg2, arg3, arg4, arg5);
}

}  // namespace junction
