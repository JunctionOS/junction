extern "C" {
#include <time.h>
}

#include "junction/base/time.h"

namespace junction {

Time Time::start_time_unix;

Status<void> InitUnixTime() {
  struct timespec curtime;

  // TODO: does this need to be more precise?
  int ret = clock_gettime(CLOCK_REALTIME, &curtime);
  Time base_time = Time::Now();

  if (unlikely(ret)) return MakeError(ret);

  Time unix_time(curtime);
  Duration micros_since_start = base_time - Time(0);
  Time::SetStartTimeUnix(unix_time - micros_since_start);
  return {};
}

}  // namespace junction
