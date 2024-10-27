// time.cc - support for time keeping functions

#include "junction/base/time.h"

#include "junction/bindings/log.h"
#include "junction/bindings/timer.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

// Junction uses a microsecond-resolution unix time monotonic clock for all
// clock types.

long usys_gettimeofday(struct timeval *tv,
                       [[maybe_unused]] struct timezone *tz) {
  *tv = Time::Now().TimevalUnixTime();
  return 0;
}

long usys_settimeofday([[maybe_unused]] const struct timeval *tv,
                       [[maybe_unused]] const struct timezone *tz) {
  return -EPERM;
}

long usys_clock_getres([[maybe_unused]] clockid_t clockid,
                       struct timespec *res) {
  res->tv_sec = 0;
  res->tv_nsec = 1000;
  return 0;
}

long usys_times(struct tms *buf) {
  buf->tms_stime = 0;
  buf->tms_cutime = buf->tms_cstime = 0;
  buf->tms_utime = myproc().GetRuntime().Seconds() *
                   static_cast<double>(sysconf(_SC_CLK_TCK));
  return 0;
}

long usys_clock_gettime(clockid_t clockid, struct timespec *tp) {
  if (clockid == CLOCK_THREAD_CPUTIME_ID) {
    *tp = mythread().GetRuntime().Timespec();
    return 0;
  }

  if (clockid == CLOCK_PROCESS_CPUTIME_ID) {
    *tp = myproc().GetRuntime().Timespec();
    return 0;
  }

  *tp = Time::Now().TimespecUnixTime();
  return 0;
}

time_t usys_time(time_t *tloc) {
  time_t val = Time::Now().TimespecUnixTime().tv_sec;
  if (tloc) *tloc = val;
  return val;
}

long usys_clock_nanosleep(clockid_t clockid, int flags,
                          const struct timespec *request,
                          struct timespec *remain) {
  if (!request) return -EINVAL;

  Time end_time;
  if (flags & TIMER_ABSTIME)
    end_time = Time::FromUnixTime(*request);
  else
    end_time = Time::Now() + Duration(*request);

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
