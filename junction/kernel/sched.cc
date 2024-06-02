// sched.cc - CPU scheduling system calls
//
extern "C" {
#include <linux/sched.h>
}

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

long usys_getcpu(unsigned *cpu, unsigned *node,
                 [[maybe_unused]] struct getcpu_cache *cache) {
  unsigned int tmp;
  {
    rt::Preempt p;
    rt::PreemptGuard g(p);
    tmp = p.get_cpu();
  }

  if (cpu) *cpu = tmp;
  if (node) *node = 0;
  return 0;
}

long usys_sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
  // Fake response that can be used by programs to detect the number of cores
  size_t cores = rt::RuntimeMaxCores();
  if (cores / kBitsPerByte > cpusetsize) return -EPERM;
  std::memset(mask, 0, cpusetsize);
  for (size_t i = 0; i < cores; ++i) CPU_SET(i, mask);
  return static_cast<int>(cpusetsize);
}

long usys_sched_setscheduler([[maybe_unused]] pid_t pid,
                             [[maybe_unused]] int policy,
                             [[maybe_unused]] const struct sched_param *param) {
  return -EPERM;
}

long usys_sched_getscheduler([[maybe_unused]] pid_t pid) { return SCHED_OTHER; }

long usys_sched_setparam(pid_t pid, const struct sched_param *param) {
  return -EPERM;
}

long usys_sched_getparam(pid_t pid, struct sched_param *param) { return 0; }

long usys_sched_get_priority_max([[maybe_unused]] int policy) { return 0; }

long usys_sched_get_priority_min([[maybe_unused]] int policy) { return 0; }

}  // namespace junction
