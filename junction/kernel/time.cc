// time.cc - support for time keeping functions

#include "junction/base/time.h"

#include "junction/bindings/timer.h"
#include "junction/kernel/usys.h"

namespace junction {

long usys_clock_nanosleep(clockid_t clockid, int flags,
                          const struct timespec *request,
                          struct timespec *remain) {
  if (!request) return -EINVAL;
  rt::Sleep(Duration(*request));
  if (remain) {
    remain->tv_sec = 0;
    remain->tv_nsec = 0;
  }
  return 0;
}

long usys_nanosleep(const struct timespec *req, struct timespec *rem) {
  rt::Sleep(Duration(*req));
  return 0;
}

}  // namespace junction
