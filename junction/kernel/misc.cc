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

inline constexpr rlim_t kRlimInfinity = RLIM_INFINITY;

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

const std::map<int, rlim_t> default_rlimits{
    {RLIMIT_AS, kRlimInfinity},
    {RLIMIT_CORE, kRlimInfinity},
    {RLIMIT_CPU, kRlimInfinity},
    {RLIMIT_DATA, kRlimInfinity},
    {RLIMIT_FSIZE, kRlimInfinity},
    {RLIMIT_LOCKS, kRlimInfinity},
    {RLIMIT_MEMLOCK, kRlimInfinity},
    {RLIMIT_MSGQUEUE, 819200},
    {RLIMIT_NICE, 0},
    {RLIMIT_NOFILE, 1000000},
    {RLIMIT_NPROC, 4000000},
    {RLIMIT_RSS, kRlimInfinity},
    {RLIMIT_RTPRIO, 0},
    {RLIMIT_RTTIME, kRlimInfinity},
    {RLIMIT_SIGPENDING, 254354},
    {RLIMIT_STACK, 67108864},
};

Status<rlim_t> GetDefaultRlim(int resource) {
  auto it = default_rlimits.find(resource);
  if (unlikely(it == default_rlimits.end())) return MakeError(EINVAL);
  return it->second;
}

long usys_getrlimit(int resource, struct rlimit *rlim) {
  Status<rlimit> ret = myproc().get_limits().GetLimit(resource);
  if (!ret) return MakeCError(ret);
  *rlim = *ret;
  return 0;
}

long usys_setrlimit(int resource, const struct rlimit *rlim) {
  myproc().get_limits().SetLimit(resource, *rlim);
  return 0;
}

long usys_prlimit64(pid_t pid, int resource, const struct rlimit *new_limit,
                    struct rlimit *old_limit) {
  std::shared_ptr<Process> p;
  if (pid != 0) {
    p = Process::Find(pid);
    if (!p) return -ESRCH;
  }

  Limits &lim = pid ? p->get_limits() : myproc().get_limits();
  if (old_limit) {
    Status<rlimit> ret = lim.GetLimit(resource);
    if (!ret) return MakeCError(ret);
    *old_limit = *ret;
  }

  if (new_limit) lim.SetLimit(resource, *new_limit);
  return 0;
}

long usys_getuid() { return mythread().get_creds().ruid; }
long usys_geteuid() { return mythread().get_creds().euid; }
long usys_getgid() { return mythread().get_creds().rgid; }
long usys_getegid() { return mythread().get_creds().egid; }

long usys_setgid(gid_t gid) {
  Credential &creds = mythread().get_creds();
  creds.rgid = creds.egid = creds.sgid = gid;
  return 0;
}

long usys_setegid(gid_t gid) {
  mythread().get_creds().egid = gid;
  return 0;
}

long usys_setuid(uid_t uid) {
  Credential &creds = mythread().get_creds();
  creds.ruid = creds.euid = creds.suid = uid;
  return 0;
}

long usys_seteuid(uid_t uid) {
  mythread().get_creds().euid = uid;
  return 0;
}

long usys_setgroups(size_t size, const gid_t *list) {
  std::vector<gid_t> &groups = mythread().get_creds().supplementary_groups;
  groups.resize(size);
  std::memcpy(groups.data(), list, sizeof(gid_t) * size);
  return 0;
}

long usys_getgroups(int size, gid_t *list) {
  std::vector<gid_t> &groups = mythread().get_creds().supplementary_groups;
  size_t nr_gids = groups.size();
  if (size) {
    if (size < static_cast<ssize_t>(nr_gids)) return -EINVAL;
    std::memcpy(list, groups.data(), sizeof(gid_t) * nr_gids);
  }
  return nr_gids;
}

long usys_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
  Credential &creds = mythread().get_creds();
  if (static_cast<int>(ruid) != -1) creds.ruid = ruid;
  if (static_cast<int>(euid) != -1) creds.euid = euid;
  if (static_cast<int>(suid) != -1) creds.suid = suid;
  return 0;
}

long usys_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid) {
  Credential &creds = mythread().get_creds();
  *ruid = creds.ruid;
  *euid = creds.euid;
  *suid = creds.suid;
  return 0;
}

long usys_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid) {
  Credential &creds = mythread().get_creds();
  *rgid = creds.rgid;
  *egid = creds.egid;
  *sgid = creds.sgid;
  return 0;
}

long usys_setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
  Credential &creds = mythread().get_creds();
  if (static_cast<int>(rgid) != -1) creds.rgid = rgid;
  if (static_cast<int>(egid) != -1) creds.egid = egid;
  if (static_cast<int>(sgid) != -1) creds.sgid = sgid;
  return 0;
}

long usys_prctl(long op, long arg1, long arg2, long arg3, long arg4,
                long arg5) {
  if (op == PR_CAPBSET_READ) {
    long cap = arg1;
    if (mythread().get_creds().in_bounding_set(cap)) return 1;
    return 0;
  }

  Status<void> ret;
  if (op == PR_CAPBSET_DROP) {
    long cap = arg1;
    ret = mythread().get_creds().DropBoundedCap(cap);
  } else if (op == PR_CAP_AMBIENT) {
    long subop = arg1;
    long cap = arg2;
    if (subop == PR_CAP_AMBIENT_RAISE) {
      ret = mythread().get_creds().AmbientRaise(cap);
    } else if (subop == PR_CAP_AMBIENT_LOWER) {
      ret = mythread().get_creds().AmbientLower(cap);
    } else if (subop == PR_CAP_AMBIENT_CLEAR_ALL) {
      mythread().get_creds().AmbientClear();
      return 0;
    } else if (subop == PR_CAP_AMBIENT_IS_SET) {
      if (mythread().get_creds().in_ambient_set(cap)) return 1;
      return 0;
    }
  } else {
    return 0;
  }
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_capset(cap_user_header_t hdrp, const cap_user_data_t datap) {
  if (hdrp->version < _LINUX_CAPABILITY_VERSION_2) return -EINVAL;
  Status<void> ret = mythread().get_creds().UpdateCapabilities(
      datap->permitted, datap->effective, datap->inheritable);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_capget(cap_user_header_t hdrp, cap_user_data_t datap) {
  if (hdrp->version == 0) {
    hdrp->version = _LINUX_CAPABILITY_VERSION_2;
    return 0;
  }

  if (!datap) return 0;

  Credential &creds = mythread().get_creds();

  datap[0].effective = creds.effective;
  datap[0].permitted = creds.permitted;
  datap[0].inheritable = creds.inheritable;

  if (hdrp->version > _LINUX_CAPABILITY_VERSION_1) {
    datap[1].effective = creds.effective >> 32;
    datap[1].permitted = creds.permitted >> 32;
    datap[1].inheritable = creds.inheritable >> 32;
  }

  return 0;
}

}  // namespace junction
