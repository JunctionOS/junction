// wait.h - allows locks to block and wait for events
//
// These utilities should generally be used instead of the low level runtime
// ones, but they are only usable for kernel threads (i.e., threads handling
// system calls).

#pragma once

#include <functional>

#include "junction/base/error.h"
#include "junction/base/time.h"
#include "junction/bindings/sync.h"
#include "junction/bindings/timer.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/signal.h"

namespace junction {

//
// Waking API
//
// This API is designed to be armed without holding the waiter's lock to reduce
// the size of critical sections. It's also composable, so that different
// events can be used with different types of waiters.
//
// Example: Wait for a condition, 10ms timeout, or pending signal...
//  rt::Spin lock;
//  WaitQueue q;
//  WakeOnTimeout timeout(lock, q, 10_ms);
//  WakeOnSignal signal(lock, q);
//  {
//    rt::SpinGuard g(lock);
//    q.Wait(lock, [&timeout, &signal] { return cond || timeout || signal; });
//    // Do something
//  }

// Wakable is a concept for blocking mechanisms that can be woken up
template <typename T>
concept Wakeable = requires(T t, thread_t *th) {
  { t.Arm() };
  { t.WakeThread(th) };
};

// WakeOnTimeout wakes a waiter when a timer expires.
template <Wakeable T>
class WakeOnTimeout {
 public:
  [[nodiscard]] WakeOnTimeout(rt::Spin &lock, T &waker, Duration timeout,
                              Thread &th = mythread())
      : end_time_(Time::Now() + timeout),
        lock_(lock),
        waker_(waker),
        th_(th),
        timer_([this] { DoWake(); }) {
    timer_.StartAt(end_time_);
  }
  [[nodiscard]] WakeOnTimeout(rt::Spin &lock, T &waker, Time timeout,
                              Thread &th = mythread())
      : end_time_(timeout), lock_(lock), waker_(waker), th_(th), timer_([this] {
          DoWake();
        }) {
    timer_.StartAt(end_time_);
  }
  [[nodiscard]] WakeOnTimeout(rt::Spin &lock, T &waker,
                              std::optional<Duration> timeout,
                              Thread &th = mythread())
      : lock_(lock), waker_(waker), th_(th), timer_([this] { DoWake(); }) {
    if (timeout && !timeout->IsZero()) {
      end_time_ = Time::Now() + *timeout;
      timer_.StartAt(end_time_);
    }
  }
  [[nodiscard]] WakeOnTimeout(rt::Spin &lock, T &waker,
                              std::optional<Time> timeout,
                              Thread &th = mythread())
      : lock_(lock), waker_(waker), th_(th), timer_([this] { DoWake(); }) {
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
  Duration TimeLeft() const {
    Duration d = Duration::Until(end_time_);
    if (d < Duration(0)) return Duration(0);
    return d;
  }

 private:
  void DoWake() {
    rt::SpinGuard g(lock_);
    timed_out_ = true;
    waker_.WakeThread(th_.GetCaladanThread());
  }

  Time end_time_;
  rt::Spin &lock_;
  T &waker_;
  Thread &th_;
  bool timed_out_{false};
  rt::Timer<std::function<void()>> timer_;
};

// WakeOnSignal wakes a waiter when a signal is delivered.
// @lock must be valid through an RCU period or be scoped to this thread's
// lifetime
class WakeOnSignal {
 public:
  [[nodiscard]] WakeOnSignal(rt::Spin &lock,
                             std::optional<k_sigset_t> mask = std::nullopt)
      : lock_(lock) {
    if (mask) {
      ThreadSignalHandler &hand = mythread().get_sighand();
      hand.SaveBlocked();
      hand.SigProcMask(SIG_SETMASK, &*mask, nullptr);
    }
    register_waker_lock(&lock_.lock_);
  }
  ~WakeOnSignal() {
    clear_waker_lock();
    if (!mythread().needs_interrupt())
      mythread().get_sighand().RestoreBlocked();
  }

  // disable copy and move.
  WakeOnSignal(const WakeOnSignal &) = delete;
  WakeOnSignal &operator=(const WakeOnSignal &) = delete;
  WakeOnSignal(WakeOnSignal &&) = delete;
  WakeOnSignal &operator=(WakeOnSignal &&) = delete;

  explicit operator bool() const { return mythread().needs_interrupt(); }

 private:
  rt::Spin &lock_;
};

}  // namespace junction