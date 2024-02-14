// sync.cc - synchronization primitives
//
// TODO(amb): Add better fairness to SharedMutex?

#include "junction/bindings/sync.h"
#include "junction/bindings/timer.h"

namespace junction::rt {

void Mutex::Lock() {
  UniqueLock ul(lock_);
  if (held_) {
    WaitNoRecheck(std::move(ul), queue_);
    return;
  }
  held_ = true;
}

bool Mutex::TryLock() {
  SpinGuard g(lock_);
  if (held_) return false;
  held_ = true;
  return true;
}

bool Mutex::InterruptibleLock() {
  UniqueLock ul(lock_);
  if (held_) return WaitInterruptibleNoRecheck(std::move(ul), queue_);
  held_ = true;
  return true;
}

void Mutex::Unlock() {
  SpinGuard g(lock_);
  if (queue_) {
    queue_.WakeOne();
  } else {
    held_ = false;
  }
}

void SharedMutex::WakeAllShared(WaitQueue &dst) {
  assert(lock_.IsHeld());
  cnt_ = std::exchange(shared_cnt_, 0);
  dst.Splice(shared_queue_);
}

void SharedMutex::WakeOneExclusive(WaitQueue &dst) {
  assert(lock_.IsHeld());
  cnt_ = -1;
  if (exclusive_queue_) dst.Arm(exclusive_queue_.Pop());
}

void SharedMutex::Lock() {
  UniqueLock ul(lock_);
  if (cnt_ != 0) {
    WaitNoRecheck(std::move(ul), exclusive_queue_);
    return;
  }
  cnt_ = -1;
}

bool SharedMutex::TryLock() {
  SpinGuard g(lock_);
  if (cnt_ != 0) return false;
  cnt_ = -1;
  return true;
}

bool SharedMutex::InterruptibleLock() {
  UniqueLock ul(lock_);
  if (cnt_ != 0)
    return WaitInterruptibleNoRecheck(std::move(ul), exclusive_queue_);
  cnt_ = -1;
  return true;
}

void SharedMutex::Unlock() {
  WaitQueue tmp;
  {
    SpinGuard g(lock_);
    assert(cnt_ == -1);
    if (shared_queue_) {
      WakeAllShared(tmp);
    } else if (exclusive_queue_) {
      WakeOneExclusive(tmp);
    } else {
      cnt_ = 0;
    }
  }
  tmp.WakeAll();
}

void SharedMutex::LockShared() {
  UniqueLock ul(lock_);
  if (cnt_ < 0) {
    shared_cnt_++;
    WaitNoRecheck(std::move(ul), shared_queue_);
    return;
  }
  cnt_++;
}

bool SharedMutex::TryLockShared() {
  SpinGuard g(lock_);
  if (cnt_ < 0) return false;
  cnt_++;
  return true;
}

bool SharedMutex::InterruptibleLockShared() {
  UniqueLock ul(lock_);
  if (cnt_ < 0) {
    shared_cnt_++;
    return WaitInterruptibleNoRecheck(std::move(ul), shared_queue_);
  }
  cnt_++;
  return true;
}

void SharedMutex::UnlockShared() {
  WaitQueue tmp;
  {
    SpinGuard g(lock_);
    assert(cnt_ > 0);
    cnt_--;
    if (cnt_ > 0) return;  // check if shared locks still held
    if (exclusive_queue_) WakeOneExclusive(tmp);
  }
  tmp.WakeOne();
}

__always_inline bool ConditionVariable::DoWait(bool block,
                                               const bool *timeout) {
  assert(lock_->IsHeld());
  UniqueLock ul(lock_->lock_);
  if (timeout && *timeout) return true;
  if (lock_->queue_) {
    lock_->queue_.WakeOne();
  } else {
    lock_->held_ = false;
  }
  if (block) return WaitInterruptibleNoRecheck(std::move(ul), queue_);
  WaitNoRecheck(std::move(ul), queue_);
  return true;
}

void ConditionVariable::Wait(Mutex &mu) {
  assert(!lock_ || lock_ == &mu);
  lock_ = &mu;
  DoWait(false);
}

bool ConditionVariable::WaitFor(Mutex &mu, Duration d) {
  assert(!lock_ || lock_ == &mu);
  lock_ = &mu;
  bool timeout;
  Timer timer(TimeoutHandler(timeout), d);
  DoWait(false, &timeout);
  if (timeout) return false;
  return true;
}

bool ConditionVariable::WaitUntil(Mutex &mu, Time t) {
  assert(!lock_ || lock_ == &mu);
  lock_ = &mu;
  bool timeout;
  Timer timer(TimeoutHandler(timeout), t);
  DoWait(false, &timeout);
  if (timeout) return false;
  return true;
}

bool ConditionVariable::WaitInterruptible(Mutex &mu) {
  assert(!lock_ || lock_ == &mu);
  lock_ = &mu;
  return DoWait(true);
}

Status<void> ConditionVariable::WaitInterruptibleFor(Mutex &mu, Duration d) {
  assert(!lock_ || lock_ == &mu);
  lock_ = &mu;
  bool timeout;
  Timer timer(TimeoutHandler(timeout), d);
  if (!DoWait(true, &timeout)) return MakeError(EINTR);
  if (timeout) return MakeError(ETIMEDOUT);
  return {};
}

Status<void> ConditionVariable::WaitInterruptibleUntil(Mutex &mu, Time t) {
  assert(!lock_ || lock_ == &mu);
  lock_ = &mu;
  bool timeout;
  Timer timer(TimeoutHandler(timeout), t);
  if (!DoWait(true, &timeout)) return MakeError(EINTR);
  if (timeout) return MakeError(ETIMEDOUT);
  return {};
}

void ConditionVariable::Notify() {
  // Wait() has never been called before, so nothing to notify
  if (!lock_) return;

  // try to notify one waiter
  Mutex &mu = *lock_;
  SpinGuard g(mu.lock_);
  if (mu.held_) {
    thread_t *th = queue_.Pop();
    if (th) mu.queue_.Arm(th);
    return;
  }
  if (queue_.WakeOne()) mu.held_ = true;
}

void ConditionVariable::NotifyAll() {
  // Wait() has never been called before, so nothing to notify
  if (!lock_) return;

  // try to notify all waiters
  Mutex &mu = *lock_;
  SpinGuard g(mu.lock_);
  mu.queue_.Splice(queue_);
  if (mu.held_) return;
  if (mu.queue_.WakeOne()) mu.held_ = true;
}

void Latch::CountDown(int count) {
  assert(count >= 0);
  SpinGuard g(lock_);
  cnt_ -= count;
  if (cnt_ <= 0) queue_.WakeAll();
}

void Latch::Wait() {
  UniqueLock ul(lock_);
  if (cnt_ <= 0) return;
  WaitNoRecheck(std::move(ul), queue_);
}

void Latch::ArriveAndWait(int count) {
  assert(count >= 0);
  UniqueLock ul(lock_);
  cnt_ -= count;
  if (cnt_ <= 0) {
    queue_.WakeAll();
    return;
  }
  WaitNoRecheck(std::move(ul), queue_);
}

bool Latch::WaitInterruptible() {
  UniqueLock ul(lock_);
  if (cnt_ <= 0) return true;
  return WaitInterruptibleNoRecheck(std::move(ul), queue_);
}

bool Latch::ArriveAndWaitInterruptible(int count) {
  assert(count >= 0);
  UniqueLock ul(lock_);
  cnt_ -= count;
  if (cnt_ <= 0) {
    queue_.WakeAll();
    return true;
  }
  return WaitInterruptibleNoRecheck(std::move(ul), queue_);
}

bool Latch::POSIXWaitInterruptible(bool *serial_thread) {
  UniqueLock ul(lock_);
  if (--cnt_ <= 0) {
    if (serial_thread) *serial_thread = true;
    queue_.WakeAll();
    return true;
  }
  if (!WaitInterruptibleNoRecheck(std::move(ul), queue_)) return false;
  if (serial_thread) *serial_thread = false;
  return true;
}

}  // namespace junction::rt
