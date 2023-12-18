// timer.h - support for timers

#pragma once

extern "C" {
#include <base/time.h>
#include <runtime/timer.h>
}

#include <functional>
#include <optional>
#include <utility>

#include "junction/base/compiler.h"
#include "junction/base/time.h"
#include "junction/bindings/sync.h"

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
    start_time_ = Time::Now() + d;
    timer_start(&entry_, start_time_.Microseconds());
  }

  // StartAt arms the timer to fire at a point in time.
  void StartAt(Time t) {
    start_time_ = t;
    timer_start(&entry_, t.Microseconds());
  }

  // Cancel stops the timer after it was armed. Returns the duration left if
  // the cancellation was successful (i.e., the timer did not already fire).
  std::optional<Duration> Cancel() {
    if (!timer_cancel(&entry_)) return std::nullopt;
    return Duration::Until(start_time_);
  }

 private:
  void Run() override { func_(); }

  struct timer_entry entry_;
  std::decay_t<Callable> func_;
  Time start_time_;
};

// Busy-spins for a duration.
inline void Delay(Duration d) { delay_us(d.Microseconds()); }

// Sleeps (blocks and reschedules) until a point in time.
inline void SleepUntil(Time t) { timer_sleep_until(t.Microseconds()); }

// Sleeps (blocks and reschedules) for a duration.
inline void Sleep(Duration d) { timer_sleep(d.Microseconds()); }

// Sleeps until a point in time, wakes up if a signal is pending
inline void SleepInterruptibleUntil(Time t) {
  __timer_sleep_interruptible(t.Microseconds());
}

// Sleeps for a duration, wakes up if a signal is pending
inline void SleepInterruptible(Duration d) {
  timer_sleep_interruptible(d.Microseconds());
}

// WakeOnTimeout wakes the running thread (if it later blocks) when a timer
// expires.
//
// This API is designed to be armed without holding the waiter's lock to reduce
// the size of critical sections.
//
// Example: Wait for a condition or a 10ms timeout.
//  rt::Spin lock;
//  rt::ThreadWaker w;
//  WakeOnTimeout timeout(lock, w, 10_ms);
//  {
//    rt::SpinGuard g(lock);
//    Wait(lock, w, [&timeout] { return cond || timeout; });
//    // Do something
//  }
template <Wakeable T>
class WakeOnTimeout {
 public:
  [[nodiscard]] WakeOnTimeout(Spin &lock, T &waker, Duration timeout)
      : end_time_(Time::Now() + timeout),
        lock_(lock),
        waker_(waker),
        timer_([this] { DoWake(); }) {
    timer_.StartAt(end_time_);
  }
  [[nodiscard]] WakeOnTimeout(Spin &lock, T &waker, Time timeout)
      : end_time_(timeout),
        lock_(lock),
        waker_(waker),
        timer_([this] { DoWake(); }) {
    timer_.StartAt(end_time_);
  }
  [[nodiscard]] WakeOnTimeout(Spin &lock, T &waker,
                              std::optional<Duration> timeout)
      : lock_(lock), waker_(waker), timer_([this] { DoWake(); }) {
    if (timeout) {
      end_time_ = Time::Now() + *timeout;
      timer_.StartAt(end_time_);
    }
  }
  [[nodiscard]] WakeOnTimeout(Spin &lock, T &waker, std::optional<Time> timeout)
      : lock_(lock), waker_(waker), timer_([this] { DoWake(); }) {
    if (timeout) {
      end_time_ = *timeout;
      timer_.StartAt(end_time_);
    }
  }
  ~WakeOnTimeout() { Stop(); }

  // disable copy and move.
  WakeOnTimeout(const WakeOnTimeout &) = delete;
  WakeOnTimeout &operator=(const WakeOnTimeout &) = delete;
  WakeOnTimeout(WakeOnTimeout &&) = delete;
  WakeOnTimeout &operator=(WakeOnTimeout &&) = delete;

  explicit operator bool() const { return timed_out_; }

  // Stop cancels the timer, returning true if cancelled before firing.
  bool Stop() { return timer_.Cancel().has_value(); }

  // TimeLeft returns the duration until the timer expires. If the timer is
  // unarmed because of an optional duration or time, the behavior is
  // undefined.
  [[nodiscard]] Duration TimeLeft() const {
    Duration d = Duration::Until(end_time_);
    if (d < Duration(0)) return Duration(0);
    return d;
  }

 private:
  void DoWake() {
    rt::SpinGuard g(lock_);
    if (waker_.WakeThread(th_)) timed_out_ = true;
  }

  Time end_time_;
  Spin &lock_;
  T &waker_;
  thread_t *th_{thread_self()};
  bool timed_out_{false};
  Timer<std::function<void()>> timer_;
};

}  // namespace junction::rt
