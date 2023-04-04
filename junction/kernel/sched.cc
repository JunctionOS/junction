// sched.cc - CPU scheduling system calls

#include <cstring>

#include "junction/base/bits.h"
#include "junction/bindings/runtime.h"
#include "junction/bindings/sync.h"
#include "junction/bindings/thread.h"
#include "junction/kernel/usys.h"

namespace junction {

long usys_sched_yield() {
  rt::Yield();
  return 0;
}

long usys_getcpu() { return rt::Preempt::get_cpu(); }

int usys_sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
  // Fake response that can be used by programs to detect the number of cores
  size_t cores = rt::RuntimeMaxCores();
  if (cores / kBitsPerByte > cpusetsize) return -EPERM;
  std::memset(mask, 0, cpusetsize);
  for (size_t i = 0; i < cores; ++i) CPU_SET(i, mask);
  return static_cast<int>(cpusetsize);
}

}  // namespace junction
