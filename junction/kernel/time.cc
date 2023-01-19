// time.cc - support for time keeping functions
#include "junction/bindings/timer.h"
#include "junction/kernel/usys.h"

namespace junction {

long usys_nanosleep(const struct timespec *req, struct timespec *rem) {
  uint64_t time_us = req->tv_sec * rt::kSeconds + req->tv_nsec / 1000;
  rt::Sleep(time_us);
  return 0;
}

}  // namespace junction
