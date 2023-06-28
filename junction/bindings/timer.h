// timer.h - support for timers

#pragma once

extern "C" {
#include <base/time.h>
#include <runtime/timer.h>
}

#include <utility>

#include "junction/base/compiler.h"

namespace junction::rt {

namespace timer_internal {

struct timer_node {
  virtual void Run() = 0;
};

extern "C" void TimerTrampoline(unsigned long arg);

}  // namespace timer_internal

inline constexpr uint64_t kMilliseconds = 1000;
inline constexpr uint64_t kSeconds = 1000000;

template <std::invocable<> Callable>
class Timer : private timer_internal::timer_node {
 public:
  explicit Timer(Callable &&func) noexcept
      : func_(std::forward<Callable>(func)) {
    auto arg = reinterpret_cast<unsigned long>(static_cast<timer_node *>(this));
    timer_init(&entry_, timer_internal::TimerTrampoline, arg);
  }
  Timer(uint64_t us, Callable &&func) noexcept
      : func_(std::forward<Callable>(func)) {
    auto arg = reinterpret_cast<unsigned long>(static_cast<timer_node *>(this));
    timer_init(&entry_, timer_internal::TimerTrampoline, arg);
    timer_start(&entry_, us);
  }
  ~Timer() { BUG_ON(timer_busy(&entry_)); }

  // Disable move.
  Timer(Timer &&) = delete;
  Timer &operator=(Timer &&) = delete;

  // Copy constructor is needed so that Timer can be inserted into containers.
  // After copying, a timer starts out disarmed.
  Timer(const Timer &t) : func_(t.func_) {
    auto arg = reinterpret_cast<unsigned long>(static_cast<timer_node *>(this));
    timer_init(&entry_, timer_internal::TimerTrampoline, arg);
  }
  Timer &operator=(const Timer &t) { func_ = t.func_; }

  // Arms the timer to fire after a microsecond duration.
  void Start(uint64_t us) { timer_start(&entry_, microtime() + us); }

  // Cancels the timer after it was armed. Returns true if the cancellation was
  // successful (i.e., the timer did not already fire).
  bool Cancel() { return timer_cancel(&entry_); }

 private:
  void Run() override { func_(); }

  struct timer_entry entry_;
  std::decay_t<Callable> func_;
};

// Gets the current number of microseconds since the launch of the runtime.
inline uint64_t MicroTime() { return microtime(); }

// Busy-spins for a microsecond duration.
inline void Delay(uint64_t us) { delay_us(us); }

// Sleeps until a microsecond deadline.
inline void SleepUntil(uint64_t deadline_us) { timer_sleep_until(deadline_us); }

// Sleeps for a microsecond duration.
inline void Sleep(uint64_t duration_us) { timer_sleep(duration_us); }

}  // namespace junction::rt
