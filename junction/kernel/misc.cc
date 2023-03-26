// misc.cc - miscellaneous system calls

extern "C" {
#include <asm/unistd_64.h>
#include <sys/resource.h>
#include <sys/utsname.h>
}

#include <cstring>

#include "junction/bindings/log.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/usys.h"

namespace junction {

namespace {
utsname utsname = {.sysname = "Linux",
                   .nodename = "junction",  // TODO: support hostnames?
                   .release = "5.19.0",     // pretend to be this kernel
                   .version = "#1 SMP",
                   .machine = "x86_64"};
}

int usys_socketpair(int domain, int type, int protocol, int sv[2]) {
  sv[0] = sv[1] = 0;
  return 0;
}

long usys_uname(struct utsname *buf) {
  if (!buf) return -EFAULT;
  std::memcpy(buf, &utsname, sizeof(utsname));
  return 0;
}

long usys_getrlimit([[maybe_unused]] int resource, struct rlimit *rlim) {
  if (!rlim) return -EFAULT;
  rlim->rlim_cur = 1024;
  rlim->rlim_max = 1024;
  return 0;
}

long usys_setrlimit([[maybe_unused]] int resource,
                    [[maybe_unused]] const struct rlimit *rlim) {
  // TODO(girfan): Should return -EPERM but some applications (memcached)
  // fail on that.
  LOG_ONCE(WARN) << "Unsupported: setrlimit";
  return 0;
}

long usys_prlimit64([[maybe_unused]] pid_t pid, [[maybe_unused]] int resource,
                    [[maybe_unused]] const struct rlimit *new_limit,
                    struct rlimit *old_limit) {
  if (new_limit) {
    // TODO(girfan): Should return -EPERM but some applications (memcached)
    // fail on that.
    LOG_ONCE(WARN) << "Unsupported: prlimit64";
  }
  if (old_limit) {
    old_limit->rlim_cur = 1024;
    old_limit->rlim_max = 1024;
  }
  return 0;
}

}  // namespace junction
