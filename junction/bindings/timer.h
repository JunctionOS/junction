// timer.h - support for timers

#pragma once

extern "C" {
#include <base/time.h>
#include <runtime/timer.h>
}

#include <utility>

#include "junction/base/compiler.h"
#include "junction/base/time.h"

namespace junction::rt {

namespace timer_internal {

struct timer_node {
  virtual void Run() = 0;
};

extern "C" void TimerTrampoline(unsigned long arg);

}  // namespace timer_internal

// Timer is an object that calls a function after a deadline
//
// The function runs in softirq context, so it should not block and must return
// quickly. However, it can spawn a new thread if a longer time is needed.
template <std::invocable<> Callable>
class Timer : private timer_internal::timer_node {
 public:
  explicit Timer(Callable &&func) noexcept
      : func_(std::forward<Callable>(func)) {
    auto arg = reinterpret_cast<unsigned long>(static_cast<timer_node *>(this));
    timer_init(&entry_, timer_internal::TimerTrampoline, arg);
  }
  ~Timer() { BUG_ON(timer_busy(&entry_)); }

  // disable copy and move.
  Timer(const Timer &) = delete;
  Timer &operator=(const Timer &) = delete;
  Timer(const Timer &&) = delete;
  Timer &operator=(const Timer &&) = delete;

  // Start arms the timer to fire after a duration.
  void Start(Duration d) {
    Time t = Time::Now() + d;
    timer_start(&entry_, t.Microseconds());
  }

  // StartAt arms the timer to fire at a point in time.
  void StartAt(Time t) { timer_start(&entry_, t.Microseconds()); }

  // Cancel stops the timer after it was armed. Returns true if the
  // cancellation was successful (i.e., the timer did not already fire).
  bool Cancel() { return timer_cancel(&entry_); }

 private:
  void Run() override { func_(); }

  struct timer_entry entry_;
  std::decay_t<Callable> func_;
};

// Busy-spins for a duration.
inline void Delay(Duration d) { delay_us(d.Microseconds()); }

// Sleeps (blocks and reschedules) until a point in time.
inline void SleepUntil(Time t) { timer_sleep_until(t.Microseconds()); }

// Sleeps (blocks and reschedules) for a duration.
inline void Sleep(Duration d) { timer_sleep(d.Microseconds()); }

}  // namespace junction::rt
