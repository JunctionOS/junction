// wait.h - allows locks to block and wait for events

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
//  WakeOnSignal signal(lock);
//  {
//    rt::SpinGuard g(lock);
//    g.Park(q, [&timeout, &signal] { return cond || timeout || signal; });
//    // Do something
//  }

// WakeOnTimeout wakes the running thread (if it later blocks) when a timer
// expires.
template <rt::Wakeable T>
class WakeOnTimeout {
 public:
  [[nodiscard]] WakeOnTimeout(rt::Spin &lock, T &waker, Duration timeout)
      : end_time_(Time::Now() + timeout),
        lock_(lock),
        waker_(waker),
        timer_([this] { DoWake(); }) {
    timer_.StartAt(end_time_);
  }
  [[nodiscard]] WakeOnTimeout(rt::Spin &lock, T &waker, Time timeout)
      : end_time_(timeout),
        lock_(lock),
        waker_(waker),
        timer_([this] { DoWake(); }) {
    timer_.StartAt(end_time_);
  }
  [[nodiscard]] WakeOnTimeout(rt::Spin &lock, T &waker,
                              std::optional<Duration> timeout)
      : lock_(lock), waker_(waker), timer_([this] { DoWake(); }) {
    if (timeout && !timeout->IsZero()) {
      end_time_ = Time::Now() + *timeout;
      timer_.StartAt(end_time_);
    }
  }
  [[nodiscard]] WakeOnTimeout(rt::Spin &lock, T &waker,
                              std::optional<Time> timeout)
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
    timed_out_ = true;
    waker_.WakeThread(th_);
  }

  Time end_time_;
  rt::Spin &lock_;
  T &waker_;
  thread_t *th_{thread_self()};
  bool timed_out_{false};
  rt::Timer<std::function<void()>> timer_;
};

// WaitInterruptible blocks the calling thread until a wakable object resumes it
// or a signal is delivered.
//
// A lock must be held to protect the wakeup condition state, which usually
// includes the wakable object.
//
// Returns true if this wait was interrupted by a signal.
//
// WARNING: @lock must be valid through an RCU period or be scoped to the
// calling thread's lifetime.
//
// WARNING: The calling thread must be a Junction kernel thread.
template <rt::Wakeable Waker>
bool WaitInterruptible(rt::Spin &lock, Waker &waker) {
  assert(lock.IsHeld());
  assert(IsJunctionThread());
  register_waker_lock(&lock.lock_);
  if (mythread().needs_interrupt()) {
    clear_waker_lock();
    return true;
  }
  waker.Arm();
  lock.UnlockAndPark();
  lock.Lock();
  clear_waker_lock();
  return mythread().needs_interrupt();
}

// WaitInterruptible blocks the calling thread until the predicate becomes true
// or a signal is delivered.
//
// A lock must be held to protect the wakeup condition state, which usually
// includes the wakable object.
//
// Returns true if this wait was interrupted by a signal.
//
// WARNING: @lock must be valid through an RCU period or be scoped to the
// calling thread's lifetime.
//
// WARNING: The calling thread must be a Junction kernel thread.
template <rt::Wakeable Waker, typename Predicate>
bool WaitInterruptible(rt::Spin &lock, Waker &w, Predicate stop) {
  while (!stop())
    if (WaitInterruptible(lock, w)) return true;
  return false;
}

// SigMaskGuard masks signal delivery during its lifetime. The previous signal
// mask is restored unless a signal is pending, in which the old mask is
// restored after the signal is delivered.
//
// WARNING: The calling thread must be a Junction kernel thread.
class SigMaskGuard {
 public:
  [[nodiscard]] SigMaskGuard(std::optional<k_sigset_t> mask) {
    assert(IsJunctionThread());
    if (!mask) return;

    ThreadSignalHandler &hand = mythread().get_sighand();
    hand.SaveBlocked();
    hand.SigProcMask(SIG_SETMASK, &*mask, nullptr);
  }
  ~SigMaskGuard() {
    if (!mythread().needs_interrupt())
      mythread().get_sighand().RestoreBlocked();
  }

  // disable copy and move.
  SigMaskGuard(const SigMaskGuard &) = delete;
  SigMaskGuard &operator=(const SigMaskGuard &) = delete;
  SigMaskGuard(SigMaskGuard &&) = delete;
  SigMaskGuard &operator=(SigMaskGuard &&) = delete;
};

}  // namespace junction
