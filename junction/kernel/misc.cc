// misc.cc - miscellaneous system calls

#include <cstring>

#include "junction/base/bits.h"
#include "junction/bindings/runtime.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/usys.h"

namespace junction {

int usys_sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
  // Fake response that can be used by programs to detect the number of cores
  size_t cores = rt::RuntimeMaxCores();
  if (cores / kBitsPerByte > cpusetsize) return -EPERM;
  std::memset(mask, 0, cpusetsize);
  for (size_t i = 0; i < cores; ++i) CPU_SET(i, mask);
  return 0;
}

ssize_t usys_getcwd(char *buf, size_t size) {
  // TODO(amb): Remove this once the filesystem is more there
  return ksys_default(reinterpret_cast<unsigned long>(buf), size, 0, 0, 0, 0, __NR_getcwd);
}

}  // namespace junction
