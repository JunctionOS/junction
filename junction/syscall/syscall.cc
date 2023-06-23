#include "junction/syscall/syscall.h"

#include <cstring>
#include <iostream>

#include "junction/bindings/log.h"
#include "junction/junction.h"
#include "junction/kernel/ksys.h"
#include "junction/syscall/systbl.h"

extern "C" {
#include <dlfcn.h>
}

namespace junction {

std::map<int, sysfn_t> debug_vdso_functions;

extern "C" long gettimeofday_strace(struct timeval *tv, struct timezone *tz) {
  long ret = reinterpret_cast<decltype(&gettimeofday_strace)>(
      debug_vdso_functions[SYS_gettimeofday])(tv, tz);
  LOG(INFO) << "gettimeofday(" << tv << ", " << tz << ") = " << ret;
  return ret;
}

#if 0
extern "C" long clock_getres_strace(clockid_t clockid, struct timespec *res) {
  long ret = reinterpret_cast<decltype(&clock_getres_strace)>(
      debug_vdso_functions[SYS_clock_getres])(clockid, res);
  LOG(INFO) << "clock_getres(" << clockid << ", " << res << ") = " << ret;
  return ret;
}
#endif

extern "C" long clock_gettime_strace(clockid_t clockid, struct timespec *tp) {
  long ret = reinterpret_cast<decltype(&clock_gettime_strace)>(
      debug_vdso_functions[SYS_clock_gettime])(clockid, tp);
  LOG(INFO) << "clock_gettime(" << clockid << ", " << tp << ") = " << ret;
  return ret;
}

extern "C" long time_strace(time_t *tloc) {
  long ret = reinterpret_cast<decltype(&time_strace)>(
      debug_vdso_functions[SYS_time])(tloc);
  LOG(INFO) << "time(" << tloc << ") = " << ret;
  return ret;
}

void SetupVdsoFunction(void *vdso, int sysnr, const char *fname) {
  sysfn_t fptr = reinterpret_cast<sysfn_t>(dlsym(vdso, fname));
  if (unlikely(!fptr)) {
    std::cerr << "Unable to resolve vDSO for " << fname << std::endl;
    return;
  }

  // Set trampoline table pointer directly to vdso function
  sys_tbl[sysnr] = fptr;

  if (unlikely(GetCfg().strace_enabled())) {
    debug_vdso_functions[sysnr] = fptr;
    const std::string_view fview = fname;
    if (fview == "__vdso_gettimeofday") {
      sys_tbl_strace[sysnr] = reinterpret_cast<sysfn_t>(gettimeofday_strace);
#if 0
    } else if (fview == "__vdso_clock_getres") {
      sys_tbl_strace[sysnr] = reinterpret_cast<sysfn_t>(clock_getres_strace);
#endif
    } else if (fview == "__vdso_clock_gettime") {
      sys_tbl_strace[sysnr] = reinterpret_cast<sysfn_t>(clock_gettime_strace);
    } else if (fview == "__vdso_time") {
      sys_tbl_strace[sysnr] = reinterpret_cast<sysfn_t>(time_strace);
    } else {
      panic("missing strace definition for a vdso function");
    }
  }
}

Status<void> InitVdso() {
  void *vdso = dlopen("linux-vdso.so.1", RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);

  if (!vdso) {
    std::cerr << "Unable to intialize vdso: " << dlerror() << std::endl;
    return MakeError(1);
  }

  SetupVdsoFunction(vdso, __NR_gettimeofday, "__vdso_gettimeofday");
  SetupVdsoFunction(vdso, __NR_clock_gettime, "__vdso_clock_gettime");
  SetupVdsoFunction(vdso, __NR_time, "__vdso_time");

  // TODO(jf): The vdso version of clock_getres seems to use a real syscall
  // SetupVdsoFunction(vdso, __NR_clock_getres, "__vdso_clock_getres");

  return {};
}

Status<void> SyscallInit() {
  Status<void> ret = KernelMMapFixed(SYSTBL_TRAMPOLINE_LOC, sizeof(sys_tbl),
                                     PROT_READ | PROT_WRITE, 0);
  if (unlikely(!ret)) return ret;

  ret = InitVdso();
  if (unlikely(!ret)) return ret;

  if (GetCfg().strace_enabled())
    std::memcpy(SYSTBL_TRAMPOLINE_LOC, sys_tbl_strace, sizeof(sys_tbl_strace));
  else
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
