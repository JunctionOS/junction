// time.cc - support for time keeping functions

#include "junction/base/time.h"

#include "junction/bindings/log.h"
#include "junction/bindings/timer.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

Status<Time> AbstimeToBaseTime(clockid_t clockid, const struct timespec &ts) {
  struct timespec curtime;
  int ret = ksys_clock_gettime(clockid, &curtime);
  Time base_now = Time::Now();

  if (unlikely(ret)) return MakeError(ret);

  Duration delta = Time(ts) - Time(curtime);
  return base_now + delta;
}

long usys_clock_nanosleep(clockid_t clockid, int flags,
                          const struct timespec *request,
                          struct timespec *remain) {
  if (!request) return -EINVAL;

  // TODO: check clockid

  Time end_time;
  if (flags & TIMER_ABSTIME) {
    Status<Time> tmp = AbstimeToBaseTime(clockid, *request);
    if (unlikely(!tmp)) return MakeCError(tmp);
    end_time = *tmp;
  } else {
    end_time = Time::Now() + Duration(*request);
  }

  rt::SleepInterruptibleUntil(end_time);

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
  Time end_time = Time::Now() + Duration(*req);

  rt::SleepInterruptibleUntil(end_time);

  if (mythread().needs_interrupt()) {
    if (rem) {
      Duration d = Duration::Until(end_time);
      if (d < Duration(0)) d = Duration(0);
      *rem = d.Timespec();
    }
    return -EINTR;
  }

  return 0;
}

}  // namespace junction
