// misc.cc - miscellaneous system calls

extern "C" {
#include <asm/unistd_64.h>
#include <sys/resource.h>
#include <sys/utsname.h>
}

#include "junction/kernel/ksys.h"
#include "junction/kernel/usys.h"

namespace junction {

ssize_t usys_getcwd(char *buf, size_t size) {
  // TODO(amb): Remove this once the filesystem is more there
  return ksys_default(reinterpret_cast<unsigned long>(buf), size, 0, 0, 0, 0,
                      __NR_getcwd);
}

int usys_socketpair(int domain, int type, int protocol, int sv[2]) {
  sv[0] = sv[1] = 0;
  return 0;
}

long usys_uname(struct utsname *buf) {
  // TODO(girfan): Cache at junction init and re-use?
  return ksys_default(reinterpret_cast<unsigned long>(buf), 0, 0, 0, 0, 0,
                      __NR_uname);
}

long usys_getrlimit([[maybe_unused]] int resource, struct rlimit *rlim) {
  // TODO(girfan): Cache at junction init and re-use?
  if (!rlim) return -EFAULT;
  rlim->rlim_cur = RLIM_INFINITY;
  rlim->rlim_max = RLIM_INFINITY;
  return 0;
}

long usys_setrlimit([[maybe_unused]] int resource,
                    [[maybe_unused]] const struct rlimit *rlim) {
  return -EPERM;
}

long usys_prlimit64([[maybe_unused]] pid_t pid, [[maybe_unused]] int resource,
                    [[maybe_unused]] const struct rlimit *new_limit,
                    struct rlimit *old_limit) {
  if (old_limit) {
    old_limit->rlim_cur = RLIM_INFINITY;
    old_limit->rlim_max = RLIM_INFINITY;
  }
  return 0;
}

}  // namespace junction
