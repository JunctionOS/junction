// time.cc - support for time keeping functions

#include "junction/kernel/time.h"

#include "junction/kernel/usys.h"

namespace junction {

long usys_clock_nanosleep(clockid_t clockid, int flags,
                          const struct timespec *request,
                          struct timespec *remain) {
  if (!request) return -EINVAL;
  rt::Sleep(timespec_to_us(*request));
  if (remain) {
    remain->tv_sec = 0;
    remain->tv_nsec = 0;
  }
  return 0;
}

long usys_nanosleep(const struct timespec *req, struct timespec *rem) {
  rt::Sleep(timespec_to_us(*req));
  return 0;
}

long usys_clock_gettime(clockid_t clk_id, struct timespec *tp) {
  return clock_gettime(clk_id, tp);
}

long usys_gettimeofday(struct timeval *tv, struct timezone *tz) {
  return gettimeofday(tv, tz);
}

long usys_clock_getres(clockid_t clk_id, struct timespec *res) {
  return clock_getres(clk_id, res);
}

}  // namespace junction
