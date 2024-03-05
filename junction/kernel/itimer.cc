#include "junction/kernel/itimer.h"

#include "junction/bindings/log.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

// This function is called from the softirq thread with preemption disabled
void ITimer::Run() {
  if (next_fire_) proc_.Signal(SIGALRM);
  if (interval_.IsZero()) {
    next_fire_ = std::nullopt;
    return;
  }
  next_fire_ = Time::Now() + interval_;
  timer_restart(&entry_, next_fire_->Microseconds());
}

long usys_setitimer(int which, const struct itimerval *new_value,
                    struct itimerval *old_value) {
  if (unlikely(which != ITIMER_REAL)) {
    LOG_ONCE(ERR) << "Only ITIMER_REAL is supported";
    return -EINVAL;
  }

  // Linux incorrectly assumes that a null new_value means cancel the timer.
  // We do the same...
  if (!new_value) {
    static const itimerval null_val = {{0, 0}, {0, 0}};
    new_value = &null_val;
  }

  itimerval old = myproc().get_itimer().exchange(*new_value);
  if (old_value) *old_value = old;

  return 0;
}

long usys_getitimer(int which, struct itimerval *curr_value) {
  if (unlikely(which != ITIMER_REAL)) return -EINVAL;
  *curr_value = myproc().get_itimer().get();
  return 0;
}

long usys_alarm(unsigned int seconds) {
  itimerval val = {{0, 0}, {seconds, 0}};
  myproc().get_itimer().exchange(val);
  return 0;
}

}  // namespace junction
