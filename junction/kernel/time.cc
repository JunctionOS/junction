// time.cc - support for time keeping functions

#include "junction/bindings/timer.h"
#include "junction/kernel/usys.h"

namespace junction {

long usys_nanosleep(const struct timespec *req, struct timespec *rem) {
  uint64_t time_us = req->tv_sec * rt::kSeconds + req->tv_nsec / 1000;
  rt::Sleep(time_us);
  return 0;
}

long usys_clock_gettime(clockid_t clk_id, struct timespec *tp) {
  // TODO(girfan): handle properly by passing to vDSO
  return clock_gettime(clk_id, tp);
}

}  // namespace junction
