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

// WakeOnTimeout wakes the running thread (if it later blocks) when a timer
// expires.
//
// This API is designed to be armed without holding the waiter's lock to reduce
// the size of critical sections.
//
// Example: Wait for a condition or a 10ms timeout.
//  rt::Spin lock;
//  WaitQueue q;
//  WakeOnTimeout timeout(lock, q, 10_ms);
//  {
//    rt::SpinGuard g(lock);
//    g.Park(q, [&timeout] { return cond || timeout; });
//    // Do something
//  }
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
// WARNING: The calling thread must be a Junction kernel thread.
template <rt::LockAndParkable LockParkable, rt::Wakeable Waker>
bool WaitInterruptible(LockParkable &lock, Waker &waker) {
  assert(lock.IsHeld());
  assert(IsJunctionThread());

  // Block and wait for an event.
  thread_t *th = thread_self();
  if (rt::SetInterruptible(th)) return true;
  waker.Arm(th);
  lock.UnlockAndPark();
  lock.Lock();

  // Check if a signal was delivered while blocked.
  rt::InterruptibleStatus status = rt::GetInterruptibleStatus(th);
  if (status == rt::InterruptibleStatus::kPendingAndDisarm) waker.Disarm(th);
  return status != rt::InterruptibleStatus::kNone;
}

// WaitInterruptible blocks the calling thread until the predicate becomes true
// or a signal is delivered.
//
// A lock must be held to protect the wakeup condition state, which usually
// includes the wakable object.
//
// Returns true if this wait was interrupted by a signal.
//
// WARNING: The calling thread must be a Junction kernel thread.
template <rt::LockAndParkable LockParkable, rt::Wakeable Waker,
          typename Predicate>
bool WaitInterruptible(LockParkable &lock, Waker &w, Predicate stop) {
  while (!stop())
    if (WaitInterruptible(lock, w)) return true;
  return false;
}

// SigMaskGuard masks signal delivery during its lifetime. The previous signal
// mask is restored unless a signal is pending, in which case the old mask is
// restored after the signal is delivered.
//
// WARNING: The calling thread must be a Junction kernel thread.
class SigMaskGuard {
 public:
  [[nodiscard]] explicit SigMaskGuard(std::optional<k_sigset_t> mask) {
    assert(IsJunctionThread());
    if (!mask) return;

    ThreadSignalHandler &handler = mythread().get_sighand();
    handler.ReplaceAndSaveBlocked(*mask);
  }
  [[nodiscard]] explicit SigMaskGuard(k_sigset_t mask) {
    assert(IsJunctionThread());
    ThreadSignalHandler &handler = mythread().get_sighand();
    handler.ReplaceAndSaveBlocked(mask);
  }
  ~SigMaskGuard() {
    ThreadSignalHandler &handler = mythread().get_sighand();
    if (handler.RestoreBlockedNeeded()) handler.RestoreBlocked();
  }

  // disable copy and move.
  SigMaskGuard(const SigMaskGuard &) = delete;
  SigMaskGuard &operator=(const SigMaskGuard &) = delete;
  SigMaskGuard(SigMaskGuard &&) = delete;
  SigMaskGuard &operator=(SigMaskGuard &&) = delete;
};

// An interruptible RW Mutex. This object's lifetime must be managed by RCU or
// be static.
class InterruptibleRWMutex {
 public:
  InterruptibleRWMutex() = default;
  ~InterruptibleRWMutex() = default;

  InterruptibleRWMutex(InterruptibleRWMutex &&) = delete;
  InterruptibleRWMutex &operator=(InterruptibleRWMutex &&) = delete;
  InterruptibleRWMutex(const InterruptibleRWMutex &) = delete;
  InterruptibleRWMutex &operator=(const InterruptibleRWMutex &) = delete;

  // Locks the mutex for reading. Returns false if interrupted and the lock is
  // not held.
  [[nodiscard]] bool RdLockInterruptible() {
    thread_t *th = thread_self();

    assert(IsJunctionThread());
    lock_.Lock();
    if (count_ >= 0) {
      AddReader();
      lock_.Unlock();
      return true;
    }

    if (unlikely(rt::SetInterruptible(th))) {
      lock_.Unlock();
      return false;
    }

    read_waiters_.Arm(th);
    lock_.UnlockAndPark();

    if (unlikely(rt::GetInterruptibleStatus(th) !=
                 rt::InterruptibleStatus::kNone)) {
      // We know an interrupt has happened, need to determine whether or not
      // Unlock() has also woken us.
      rt::SpinGuard g(lock_);
      if (rt::GetInterruptibleStatus(th) ==
          rt::InterruptibleStatus::kPendingAndDisarm) {
        read_waiters_.Disarm(th);
        return false;
      }
      return true;
    }

    return true;
  }

  // Locks the mutex for reading.
  void RdLock() {
    lock_.Lock();
    if (count_ >= 0) {
      AddReader();
      lock_.Unlock();
      return;
    }
    read_waiters_.Arm();
    lock_.UnlockAndPark();
  }

  // Locks the mutex for writing.
  void WrLock() {
    lock_.Lock();
    if (count_ == 0) {
      AddWriter();
      lock_.Unlock();
      return;
    }
    write_waiters_.Arm();
    lock_.UnlockAndPark();
  }

  // Locks the mutex for writing. Returns false if interrupted and the lock is
  // not held.
  [[nodiscard]] bool WrLockInterruptible() {
    thread_t *th = thread_self();
    lock_.Lock();
    if (count_ == 0) {
      AddWriter();
      lock_.Unlock();
      return true;
    }

    if (unlikely(rt::SetInterruptible(th))) {
      lock_.Unlock();
      return false;
    }

    write_waiters_.Arm(th);
    lock_.UnlockAndPark();

    if (unlikely(rt::GetInterruptibleStatus(th) !=
                 rt::InterruptibleStatus::kNone)) {
      // We know an interrupt has happened, need to determine whether or not
      // Unlock() has also woken us.
      rt::SpinGuard g(lock_);
      if (rt::GetInterruptibleStatus(th) ==
          rt::InterruptibleStatus::kPendingAndDisarm) {
        read_waiters_.Disarm(th);
        return false;
      }
      return true;
    }

    return true;
  }

  // Unlocks the mutex.
  void Unlock() {
    rt::SpinGuard g(lock_);
    assert(count_ != 0);

    count_ -= phase_;

    if (count_ == 0) {
      if (read_waiter_count_)
        WakeReadWaiters();
      else
        TryWakeOneWriter();
    }
  }

  // Locks the mutex for reading only if it is currently unlocked. Returns true
  // if successful.
  [[nodiscard]] bool TryRdLock() {
    rt::SpinGuard g(lock_);
    if (count_ < 0) return false;
    AddReader();
    return true;
  }

  // Locks the mutex for writing only if it is currently unlocked. Returns true
  // if successful.
  [[nodiscard]] bool TryWrLock() {
    rt::SpinGuard g(lock_);
    if (count_ != 0) return false;
    AddWriter();
    return true;
  }

  // Returns true if the mutex is currently held.
  [[nodiscard]] bool IsHeld() const { return access_once(count_) != 0; }

 private:
  static constexpr inline uint64_t kWaiting = 1;
  static constexpr inline uint64_t kAcquired = 2;
  static constexpr inline int kPhaseRead = 1;
  static constexpr inline int kPhaseWrite = -1;

  inline void AddReader() {
    count_++;
    phase_ = kPhaseRead;
  }

  inline void AddWriter() { count_ = phase_ = kPhaseWrite; }

  void WakeReadWaiters() {
    assert(lock_.IsHeld());
    assert(count_ == 0);

    read_waiters_.WakeAll();
    count_ = read_waiter_count_;
    read_waiter_count_ = 0;
    phase_ = kPhaseRead;
  }

  void TryWakeOneWriter() {
    assert(lock_.IsHeld());
    assert(count_ == 0);

    if (write_waiters_.WakeOne()) AddWriter();
  }

  rt::Spin lock_;
  rt::WaitQueue read_waiters_;
  rt::WaitQueue write_waiters_;
  int count_{0};
  int phase_;
  int read_waiter_count_{0};
};

}  // namespace junction
