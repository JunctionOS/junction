// misc.cc - miscellaneous system calls

extern "C" {
#include <asm/unistd_64.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
}

#include <cstring>

#include "junction/bindings/log.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

namespace {
utsname utsname = {.sysname = "Linux",
                   .nodename = "junction",  // TODO: support hostnames?
                   .release = "5.19.0",     // pretend to be this kernel
                   .version = "#1 SMP",
                   .machine = "x86_64"};
}

long usys_uname(struct utsname *buf) {
  if (!buf) return -EFAULT;
  std::memcpy(buf, &utsname, sizeof(utsname));
  return 0;
}

long usys_sysinfo(struct sysinfo *info) {
  info->uptime = microtime() / 1000000UL;
  info->loads[0] = 0;
  info->loads[1] = 0;
  info->loads[2] = 0;
  info->totalram = kMemoryMappingSize;
  info->freeram = info->totalram - myproc().get_mem_map().HeapUsage();
  info->sharedram = 0;
  info->bufferram = 0;
  info->totalswap = 0;
  info->freeswap = 0;
  info->procs = 1;  // TODO (jsf): fix
  info->totalhigh = 0;
  info->freehigh = 0;
  info->mem_unit = 1;  // bytes
  return 0;
}

long usys_getrlimit(int resource, struct rlimit *rlim) {
  if (resource != RLIMIT_NOFILE) return -EPERM;
  if (!rlim) return -EFAULT;
  rlimit limit_nofile = myproc().get_limit_nofile();
  rlim->rlim_cur = limit_nofile.rlim_cur;
  rlim->rlim_max = limit_nofile.rlim_max;
  return 0;
}

long usys_setrlimit(int resource, const struct rlimit *rlim) {
  if (resource != RLIMIT_NOFILE) return -EPERM;
  if (!rlim) return -EFAULT;
  if (rlim->rlim_cur > rlim->rlim_max) return -EINVAL;
  myproc().set_limit_nofile(rlim);
  return 0;
}

// TODO(girfan): Need to check the pid when we support multiple procs.
long usys_prlimit64([[maybe_unused]] pid_t pid, int resource,
                    const struct rlimit *new_limit, struct rlimit *old_limit) {
  if (resource != RLIMIT_NOFILE) return -EPERM;
  if (old_limit) {
    rlimit limit_nofile = myproc().get_limit_nofile();
    old_limit->rlim_cur = limit_nofile.rlim_cur;
    old_limit->rlim_max = limit_nofile.rlim_max;
  }
  if (new_limit) {
    if (new_limit->rlim_cur > new_limit->rlim_max) return -EINVAL;
    myproc().set_limit_nofile(new_limit);
  }
  return 0;
}

long usys_getuid() { return GetCfg().get_uid(); }
long usys_geteuid() { return GetCfg().get_uid(); }
long usys_getgid() { return GetCfg().get_gid(); }
long usys_getegid() { return GetCfg().get_gid(); }

long usys_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
  if (static_cast<int>(ruid) != -1 && ruid != GetCfg().get_uid())
    return -EINVAL;
  if (static_cast<int>(euid) != -1 && euid != GetCfg().get_uid())
    return -EINVAL;
  if (static_cast<int>(suid) != -1 && suid != GetCfg().get_uid())
    return -EINVAL;
  return 0;
}

long usys_setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
  if (static_cast<int>(rgid) != -1 && rgid != GetCfg().get_gid())
    return -EINVAL;
  if (static_cast<int>(egid) != -1 && egid != GetCfg().get_gid())
    return -EINVAL;
  if (static_cast<int>(sgid) != -1 && sgid != GetCfg().get_gid())
    return -EINVAL;
  return 0;
}

}  // namespace junction
