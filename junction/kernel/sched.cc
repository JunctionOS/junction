#include "junction/bindings/sync.h"
#include "junction/bindings/thread.h"
#include "junction/kernel/usys.h"

namespace junction {

long usys_sched_yield() {
  rt::Yield();
  return 0;
}

long usys_getcpu() { return rt::Preempt::get_cpu(); }

}  // namespace junction
