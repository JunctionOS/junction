// time.cc - support for time keeping functions

#include "junction/base/time.h"

#include "junction/bindings/log.h"
#include "junction/bindings/timer.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

long usys_clock_nanosleep(clockid_t clockid, int flags,
                          const struct timespec *request,
                          struct timespec *remain) {
  if (!request) return -EINVAL;

  // TODO: check clockid

  Time end_time;
  if (flags & TIMER_ABSTIME) {
    // convert absolute time to Caladan time
    struct timespec curtime;
    int ret = ksys_clock_gettime(clockid, &curtime);
    if (unlikely(ret)) {
      LOG_ONCE(ERR) << "Bad vdso gettime";
      return ret;
    }

    Time clock_start(curtime), clock_end(*request);
    if (clock_end <= clock_start) return 0;
    end_time = Time::Now() + (clock_end - clock_start);
  } else {
    end_time = Time::Now() + Duration(*request);
  }

  __timer_sleep_interruptible(end_time.Microseconds());

  if (mythread().needs_interrupt()) {
    if (remain && !(flags & TIMER_ABSTIME)) {
      Duration d = Duration::Until(end_time);
      if (d < Duration(0)) d = Duration(0);
      *remain = d.Timespec();
    }
    return -EINTR;
  }

  return 0;
}

long usys_nanosleep(const struct timespec *req, struct timespec *rem) {
  rt::Sleep(Duration(*req));
  return 0;
}

}  // namespace junction
