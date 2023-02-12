// time.cc - support for time keeping functions

#include "junction/kernel/time.h"

#include "junction/kernel/usys.h"

namespace junction {

long usys_nanosleep(const struct timespec *req, struct timespec *rem) {
  rt::Sleep(timespec_to_us(*req));
  return 0;
}

long usys_clock_gettime(clockid_t clk_id, struct timespec *tp) {
  // TODO(girfan): handle properly by passing to vDSO
  return clock_gettime(clk_id, tp);
}

}  // namespace junction
