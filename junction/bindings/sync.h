// sync.h - support for synchronization primitives

#pragma once

extern "C" {
#include <base/lock.h>
#include <base/stddef.h>
#include <runtime/sync.h>
#include <runtime/thread.h>
}

#include <type_traits>

namespace junction::rt {

// Force the compiler to access a memory location.
template <typename T>
T volatile &access_once(T &t) requires std::is_integral_v<T> {
  return static_cast<T volatile &>(t);
}

// Force the compiler to read a memory location.
template <typename T>
T read_once(const T &p) requires std::is_integral_v<T> {
  return static_cast<const T volatile &>(p);
}

// Force the compiler to write a memory location.
template <typename T>
void write_once(T &p, const T &val) requires std::is_integral_v<T> {
  static_cast<T volatile &>(p) = val;
}

// ThreadWaker is used to wake the current thread after it parks.
class ThreadWaker {
 public:
  ThreadWaker() noexcept = default;
  ~ThreadWaker() { assert(th_ == nullptr); }

  // disable copy.
  ThreadWaker(const ThreadWaker &) = delete;
  ThreadWaker &operator=(const ThreadWaker &) = delete;

  // allow move.
  ThreadWaker(ThreadWaker &&w) noexcept : th_(w.th_) { w.th_ = nullptr; }
  ThreadWaker &operator=(ThreadWaker &&w) noexcept {
    th_ = w.th_;
    w.th_ = nullptr;
    return *this;
  }

  // Prepares the running thread for waking after it parks.
  void Arm() { th_ = thread_self(); }

  // Makes the parked thread runnable. Must be called by another thread after
  // the prior thread has called Arm() and has parked (or will park in the
  // immediate future).
  void Wake(bool head = false) {
    if (th_ == nullptr) return;
    thread_t *th = std::exchange(th_, nullptr);
    if (head) {
      thread_ready_head(th);
    } else {
      thread_ready(th);
    }
  }

 private:
  thread_t *th_ = nullptr;
};

// Disables preemption across a critical section.
class Preempt {
 public:
  Preempt() noexcept = default;
  ~Preempt() = default;

  // Disables preemption.
  static void Lock() { preempt_disable(); }

  // Enables preemption.
  static void Unlock() { preempt_enable(); }

  // Atomically enables preemption and parks the running thread.
  static void UnlockAndPark() { thread_park_and_preempt_enable(); }

  // Returns true if preemption is currently disabled.
  [[nodiscard]] static bool IsHeld() { return !preempt_enabled(); }

  // Returns true if preemption is needed. Will be handled on Unlock() or on
  // UnlockAndPark().
  [[nodiscard]] static bool PreemptNeeded() {
    assert(IsHeld());
    return preempt_needed();
  }

  // Gets the current CPU index (not the same as the core number).
  [[nodiscard]] static unsigned int get_cpu() {
    assert(IsHeld());
    return perthread_read(kthread_idx);
  }

  // disable move and copy.
  Preempt(Preempt &&) = delete;
  Preempt &operator=(Preempt &&) = delete;
  Preempt(const Preempt &) = delete;
  Preempt &operator=(const Preempt &) = delete;
};

// Spin lock support.
class Spin {
 public:
  Spin() noexcept { spin_lock_init(&lock_); }
  ~Spin() { assert(!spin_lock_held(&lock_)); }

  Spin(Spin &&) = delete;
  Spin &operator=(Spin &&) = delete;
  Spin(const Spin &) = delete;
  Spin &operator=(const Spin &) = delete;

  // Locks the spin lock.
  void Lock() { spin_lock_np(&lock_); }

  // Unlocks the spin lock.
  void Unlock() { spin_unlock_np(&lock_); }

  // Atomically unlocks the spin lock and parks the running thread.
  void UnlockAndPark() { thread_park_and_unlock_np(&lock_); }

  // Locks the spin lock only if it is currently unlocked. Returns true if
  // successful.
  bool TryLock() { return spin_try_lock_np(&lock_); }

  // Returns true if the lock is currently held.
  [[nodiscard]] bool IsHeld() const { return spin_lock_held(&lock_); }

  // Returns true if preemption is needed. Will be handled on Unlock() or on
  // UnlockAndPark().
  [[nodiscard]] bool PreemptNeeded() const {
    assert(IsHeld());
    return preempt_needed();
  }

  // Gets the current CPU index (not the same as the core number).
  [[nodiscard]] unsigned int get_cpu() const {
    assert(IsHeld());
    return perthread_read(kthread_idx);
  }

 private:
  spinlock_t lock_;
};

// Pthread-like mutex support.
class Mutex {
  friend class CondVar;

 public:
  Mutex() noexcept { mutex_init(&mu_); }
  ~Mutex() { assert(!mutex_held(&mu_)); }

  Mutex(Mutex &&) = delete;
  Mutex &operator=(Mutex &&) = delete;
  Mutex(const Mutex &) = delete;
  Mutex &operator=(const Mutex &) = delete;

  // Locks the mutex.
  void Lock() { mutex_lock(&mu_); }

  // Unlocks the mutex.
  void Unlock() { mutex_unlock(&mu_); }

  // Locks the mutex only if it is currently unlocked. Returns true if
  // successful.
  bool TryLock() { return mutex_try_lock(&mu_); }

  // Returns true if the mutex is currently held.
  [[nodiscard]] bool IsHeld() const { return mutex_held(&mu_); }

 private:
  mutex_t mu_;
};

// Lockable is the concept of a lock.
template <typename T>
concept Lockable = requires(T t) {
  { t.Lock() } -> std::same_as<void>;
  { t.Unlock() } -> std::same_as<void>;
};

// LockAndParkable is the concept of a lock that can park and wait for a
// condition during unlocking.
template <typename T>
concept LockAndParkable = requires(T t) {
  { t.Lock() } -> std::same_as<void>;
  { t.UnlockAndPark() } -> std::same_as<void>;
};

// RAII lock support (works with Spin, Preempt, and Mutex).
template <typename L>
requires Lockable<L>
class ScopedLock {
 public:
  explicit ScopedLock(L *lock) noexcept : lock_(lock) { lock_->Lock(); }
  ~ScopedLock() { lock_->Unlock(); }

  ScopedLock(ScopedLock &&) = delete;
  ScopedLock &operator=(ScopedLock &&) = delete;
  ScopedLock(const ScopedLock &) = delete;
  ScopedLock &operator=(const ScopedLock &) = delete;

  // Blocks in order to wait for a condition.
  // Only works with Spin and Preempt (not Mutex).
  // Spurious wakeups are possible, so the condition must be rechecked.
  // Example:
  //   rt::ThreadWaker w;
  //   rt::SpinLock l;
  //   rt::SpinGuard guard(l);
  //   while (condition) guard.Park(&w);
  void Park(ThreadWaker *w) requires LockAndParkable<L> {
    assert(lock_->IsHeld());
    w->Arm();
    lock_->UnlockAndPark();
    lock_->Lock();
  }

  // Blocks and waits for the predicate to become true.
  // Only works with Spin and Preempt (not Mutex).
  // Example:
  //   rt::ThreadWaker w;
  //   rt::SpinLock l;
  //   rt::SpinGuard guard(l);
  //   guard.Park(&w, []{ return predicate; });
  template <typename Predicate>
  void Park(ThreadWaker *w, Predicate p) requires LockAndParkable<L> {
    assert(lock_->IsHeld());
    while (!p()) {
      w->Arm();
      lock_->UnlockAndPark();
      lock_->Lock();
    }
  }

 private:
  L *const lock_;
};

using SpinGuard = ScopedLock<Spin>;
using MutexGuard = ScopedLock<Mutex>;
using PreemptGuard = ScopedLock<Preempt>;

// RAII lock and park support (works with both Spin and Preempt).
template <typename L>
requires LockAndParkable<L>
class ScopedLockAndPark {
 public:
  explicit ScopedLockAndPark(L *lock) noexcept : lock_(lock) { lock_->Lock(); }
  ~ScopedLockAndPark() { lock_->UnlockAndPark(); }

  ScopedLockAndPark(ScopedLockAndPark &&) = delete;
  ScopedLockAndPark &operator=(ScopedLockAndPark &&) = delete;
  ScopedLockAndPark(const ScopedLockAndPark &) = delete;
  ScopedLockAndPark &operator=(const ScopedLockAndPark &) = delete;

 private:
  L *const lock_;
};

using SpinGuardAndPark = ScopedLockAndPark<Spin>;
using PreemptGuardAndPark = ScopedLockAndPark<Preempt>;

// Pthread-like condition variable support.
class CondVar {
 public:
  CondVar() noexcept { condvar_init(&cv_); };
  ~CondVar() = default;

  CondVar(CondVar &&) = delete;
  CondVar &operator=(CondVar &&) = delete;
  CondVar(const CondVar &) = delete;
  CondVar &operator=(const CondVar &) = delete;

  // Block until the condition variable is signaled. Recheck the condition
  // after wakeup, as no guarantees are made about preventing spurious wakeups.
  void Wait(Mutex *mu) { condvar_wait(&cv_, &mu->mu_); }

  // Block until a predicate is true.
  template <typename Predicate>
  void Wait(Mutex *mu, Predicate p) {
    while (!p()) condvar_wait(&cv_, &mu->mu_);
  }

  // Wake up one waiter.
  void Signal() { condvar_signal(&cv_); }

  // Wake up all waiters.
  void SignalAll() { condvar_broadcast(&cv_); }

 private:
  condvar_t cv_;
};

// Golang-like waitgroup support.
class WaitGroup {
 public:
  // initializes a waitgroup with zero jobs.
  WaitGroup() noexcept { waitgroup_init(&wg_); };

  // Initializes a waitgroup with @count jobs.
  explicit WaitGroup(int count) noexcept {
    waitgroup_init(&wg_);
    waitgroup_add(&wg_, count);
  }

  ~WaitGroup() { assert(wg_.cnt == 0); };

  WaitGroup(WaitGroup &&) = delete;
  WaitGroup &operator=(WaitGroup &&) = delete;
  WaitGroup(const WaitGroup &) = delete;
  WaitGroup &operator=(const WaitGroup &) = delete;

  // Changes the number of jobs (can be negative).
  void Add(int count) { waitgroup_add(&wg_, count); }

  // Decrements the number of jobs by one.
  void Done() { Add(-1); }

  // Block until the number of jobs reaches zero.
  void Wait() { waitgroup_wait(&wg_); }

 private:
  waitgroup_t wg_;
};

// Blocks the thread forever (doesn't return).
inline void WaitForever() {
  Preempt p;
  PreemptGuardAndPark g(&p);
}

}  // namespace junction::rt
