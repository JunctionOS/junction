// sync.h - support for synchronization primitives

#pragma once

extern "C" {
#include <base/lock.h>
#include <base/stddef.h>
#include <runtime/interruptible_wait.h>
#include <runtime/sync.h>
#include <runtime/thread.h>
}

#include <type_traits>
#include <utility>

#include "junction/base/compiler.h"

namespace junction::rt {

// Lockable is the concept of a lock.
template <typename T>
concept Lockable = requires(T t) {
  { t.Lock() } -> std::same_as<void>;
  { t.Unlock() } -> std::same_as<void>;
};

// LockAndParkable is the concept of a lock that can park and wait for a
// condition after unlocking.
template <typename T>
concept LockAndParkable = requires(T t) {
  { t.Lock() } -> std::same_as<void>;
  { t.UnlockAndPark() } -> std::same_as<void>;
};

// Wakable is a concept for blocking mechanisms that can be woken up
template <typename T>
concept Wakeable = requires(T t, thread_t *th) {
  { t.Arm(th) } -> std::same_as<void>;
  { t.Disarm(th) } -> std::same_as<void>;
  { t.WakeThread(th) } -> std::same_as<void>;
};

// SetInterruptible should be called before blocking if waking from signals is
// desired. If true, a signal is pending and the thread should return
// rather than blocking.
inline bool SetInterruptible(thread_t *th) { return prepare_interruptible(th); }

enum class InterruptibleStatus : int {
  kNone = 0,              // No signal is pending
  kPending = 1,           // A signal is pending
  kPendingAndDisarm = 2,  // A signal is pending and the waker must be disarmed
};

// GetInterruptibleStatus must be called by any thread that wakes after calling
// SetInterruptible(). The return value determines the appropriate action.
inline InterruptibleStatus GetInterruptibleStatus(thread_t *th) {
  return static_cast<InterruptibleStatus>(get_interruptible_status(th));
}

// ThreadReady wakes a blocking thread.
inline void ThreadReady(thread_t *th) {
  // Works whether MarkInterruptible() was called or not.
  interruptible_wake(th);
}

// WaitQueue is used to wake a group of threads.
class WaitQueue {
 public:
  WaitQueue() { list_head_init(&waiters_); };
  ~WaitQueue() { assert(list_empty(&waiters_)); }

  // disable copy and move.
  WaitQueue(const WaitQueue &) = delete;
  WaitQueue &operator=(const WaitQueue &) = delete;
  WaitQueue(const WaitQueue &&) = delete;
  WaitQueue &operator=(const WaitQueue &&) = delete;

  [[nodiscard]] bool empty() const { return list_empty(&waiters_); }

  // Arm prepares the running thread to block. Can only be called once,
  // must be synchronized by caller.
  void Arm(thread_t *th = thread_self()) {
    list_add_tail(&waiters_, &th->link);
  }

  // Cancel an arm, must be synchronized by caller.
  void Disarm(thread_t *th) { list_del_from(&waiters_, &th->link); }

  // Wake up to one thread waiter (must be synchronized by caller)
  // Returns true if a waiter was found and removed from the list.
  bool WakeOne() {
    thread_t *th = list_pop(&waiters_, thread_t, link);
    if (th == nullptr) return false;
    ThreadReady(th);
    return true;
  }

  // Wake all thread waiters (must be synchronized by caller)
  void WakeAll() {
    while (true) {
      thread_t *th = list_pop(&waiters_, thread_t, link);
      if (th == nullptr) return;
      ThreadReady(th);
    }
  }

  // WakeThread makes a specific thread runnable.
  // Must be synchronized by caller.
  void WakeThread(thread_t *th) {
    Disarm(th);
    ThreadReady(th);
  }

 private:
  list_head waiters_;
};

// ThreadWaker wakes one thread after it has blocked.
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

  // Arm prepares the running thread to block. Can only be called once.
  void Arm(thread_t *th = thread_self()) { th_ = th; }

  // Cancel an arm, must be synchronized by caller.
  void Disarm(thread_t *th) {
    assert(th == th_);
    th_ = nullptr;
  }

  // Wake makes the parked thread runnable. Must be called by another thread
  // after the prior thread has called Arm() and has parked (or will park in
  // the immediate future).
  void Wake() {
    if (th_ == nullptr) return;
    thread_t *th = std::exchange(th_, nullptr);
    ThreadReady(th);
  }

  // WakeThread makes a specific thread runnable. In this class, it can only be
  // the parked thread.
  void WakeThread(thread_t *th) {
    assert(!th_ || th_ == th);
    Wake();
  }

 private:
  thread_t *th_ = nullptr;
};

// Wait blocks the calling thread until a wakable object resumes it.
//
// A lock must be held to protect the wakeup condition state, which usually
// includes the wakable object.
template <LockAndParkable L, Wakeable W>
void Wait(L &lock, W &waker) {
  assert(lock.IsHeld());
  waker.Arm();
  lock.UnlockAndPark();
  lock.Lock();
}

// Disables preemption across a critical section.
class Preempt {
 public:
  Preempt() noexcept = default;
  ~Preempt() = default;

  // disable move and copy.
  Preempt(Preempt &&) = delete;
  Preempt &operator=(Preempt &&) = delete;
  Preempt(const Preempt &) = delete;
  Preempt &operator=(const Preempt &) = delete;

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
  [[nodiscard]] bool TryLock() { return spin_try_lock_np(&lock_); }

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
  [[nodiscard]] bool TryLock() { return mutex_try_lock(&mu_); }

  // Returns true if the mutex is currently held.
  [[nodiscard]] bool IsHeld() const { return mutex_held(&mu_); }

 private:
  mutex_t mu_;
};

// Pthread-like rwmutex support.
class RWMutex {
 public:
  RWMutex() noexcept { rwmutex_init(&mu_); }
  ~RWMutex() { assert(!rwmutex_held(&mu_)); }

  RWMutex(RWMutex &&) = delete;
  RWMutex &operator=(RWMutex &&) = delete;
  RWMutex(const RWMutex &) = delete;
  RWMutex &operator=(const RWMutex &) = delete;

  // Locks the mutex for reading.
  void RdLock() { rwmutex_rdlock(&mu_); }

  // Locks the mutex for writing.
  void WrLock() { rwmutex_wrlock(&mu_); }

  // Unlocks the mutex.
  void Unlock() { rwmutex_unlock(&mu_); }

  // Locks the mutex for reading only if it is currently unlocked. Returns true
  // if successful.
  [[nodiscard]] bool TryRdLock() { return rwmutex_try_rdlock(&mu_); }

  // Locks the mutex for writing only if it is currently unlocked. Returns true
  // if successful.
  [[nodiscard]] bool TryWrLock() { return rwmutex_try_wrlock(&mu_); }

  // Returns true if the mutex is currently held.
  [[nodiscard]] bool IsHeld() const { return rwmutex_held(&mu_); }

 private:
  rwmutex_t mu_;
};

// Pthread-like barrier support.
class Barrier {
 public:
  explicit Barrier(int count) noexcept { barrier_init(&b_, count); }
  ~Barrier() = default;

  Barrier(Barrier &&) = delete;
  Barrier &operator=(Barrier &&) = delete;
  Barrier(const Barrier &) = delete;
  Barrier &operator=(const Barrier &) = delete;

  // Waits on the barrier. Returns true if the calling thread released the
  // barrier.
  bool Wait() { return barrier_wait(&b_); }

 private:
  barrier_t b_;
};

// RAII lock support (works with Spin, Preempt, and Mutex).
template <Lockable L>
class ScopedLock {
 public:
  [[nodiscard]] explicit ScopedLock(L &lock) noexcept : lock_(lock) {
    lock_.Lock();
  }
  ~ScopedLock() { lock_.Unlock(); }

  ScopedLock(ScopedLock &&) = delete;
  ScopedLock &operator=(ScopedLock &&) = delete;
  ScopedLock(const ScopedLock &) = delete;
  ScopedLock &operator=(const ScopedLock &) = delete;

  // Park blocks to wait for a condition.
  // Only works with Spin and Preempt (not Mutex).
  // The condition should be rechecked after waking.
  // Example:
  //   rt::ThreadWaker w;
  //   rt::SpinLock l;
  //   rt::SpinGuard guard(l);
  //   while (condition) guard.Park(w);
  template <Wakeable Waker>
  void Park(Waker &w)
    requires LockAndParkable<L>
  {
    Wait(lock_, w);
  }

  // Park blocks and waits for the predicate to become true.
  // Only works with Spin and Preempt (not Mutex).
  // Example:
  //   rt::ThreadWaker w;
  //   rt::SpinLock l;
  //   rt::SpinGuard guard(l);
  //   guard.Park(w, []{ return predicate; });
  template <Wakeable Waker, typename Predicate>
  void Park(Waker &w, Predicate stop)
    requires LockAndParkable<L>
  {
    while (!stop()) Wait(lock_, w);
  }

 private:
  L &lock_;
};

using SpinGuard = ScopedLock<Spin>;
using MutexGuard = ScopedLock<Mutex>;
using PreemptGuard = ScopedLock<Preempt>;

// RAII lock and park support (works with both Spin and Preempt).
template <LockAndParkable L>
class ScopedLockAndPark {
 public:
  [[nodiscard]] explicit ScopedLockAndPark(L &lock) noexcept : lock_(lock) {
    lock_.Lock();
  }
  ~ScopedLockAndPark() { lock_.UnlockAndPark(); }

  ScopedLockAndPark(ScopedLockAndPark &&) = delete;
  ScopedLockAndPark &operator=(ScopedLockAndPark &&) = delete;
  ScopedLockAndPark(const ScopedLockAndPark &) = delete;
  ScopedLockAndPark &operator=(const ScopedLockAndPark &) = delete;

 private:
  L &lock_;
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
  void Wait(Mutex &mu) { condvar_wait(&cv_, &mu.mu_); }

  // Block until a predicate is true.
  template <typename Predicate>
  void Wait(Mutex &mu, Predicate stop) {
    while (!stop()) condvar_wait(&cv_, &mu.mu_);
  }

  // Block until the condition variable is signaled. If timeout us elapses
  // before a signal is generated, the function returns false.
  bool WaitFor(Mutex &mu, uint64_t timeout_us) {
    return condvar_wait_timed(&cv_, &mu.mu_, timeout_us);
  }

  // Block until a predicate is true. If timeout us elapses before a signal
  // is generated, the function returns false.
  template <typename Predicate>
  bool WaitFor(Mutex &mu, uint64_t timeout_us, Predicate stop) {
    while (!stop()) {
      if (!condvar_wait_timed(&cv_, &mu.mu_, timeout_us)) return false;
    }
    return true;
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
  PreemptGuardAndPark g(p);
}

// Reader-Writer mutex; works with C++ std::unique_lock/std::shared_lock.
class SharedMutex {
 public:
  SharedMutex() { rwmutex_init(&mu_); }
  ~SharedMutex() = default;

  // Locks the mutex in write mode.
  void lock() { rwmutex_wrlock(&mu_); }

  // Locks the mutex in write mode only if it is currently unlocked.
  // Returns true if successful.
  bool try_lock() { return rwmutex_try_wrlock(&mu_); }

  // Unlocks the mutex.
  void unlock() { rwmutex_unlock(&mu_); }

  // Locks the mutex in read mode.
  void lock_shared() { rwmutex_rdlock(&mu_); }

  // Unlocks the mutex.
  void unlock_shared() { rwmutex_unlock(&mu_); }

  // Locks the mutex in read mode only if it is currently write unlocked.
  // Returns true if successful.
  bool try_lock_shared() { return rwmutex_try_rdlock(&mu_); }

  /* no copying or moving*/
  SharedMutex(const SharedMutex &) = delete;
  SharedMutex &operator=(const SharedMutex &) = delete;
  SharedMutex(SharedMutex &&) = delete;
  SharedMutex &operator=(const SharedMutex &&) = delete;

 private:
  rwmutex_t mu_;
};

}  // namespace junction::rt
