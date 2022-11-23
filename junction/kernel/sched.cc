#include "junction/bindings/thread.h"
#include "junction/kernel/usys.h"

namespace junction {

int usys_sched_yield() {
  rt::Yield();
  return 0;
}

}  // namespace junction
