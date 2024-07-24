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
#include "junction/base/error.h"
#include "junction/base/time.h"

namespace junction::rt {

// Lockable is the concept of a lock.
template <typename T>
concept Lockable = requires(T t) {
  { t.Lock() } -> std::same_as<void>;
  { t.Unlock() } -> std::same_as<void>;
  { t.IsHeld() } -> std::same_as<bool>;
};

// TryableLock is the concept of a lock that can tried to be acquired if not
// held already.
template <typename T>
concept TryableLock = Lockable<T> && requires(T t) {
  { t.TryLock() } -> std::same_as<bool>;
};

// InterruptibleLock is the concept of a lock that can be interrupted while
// waiting to acquire.
template <typename T>
concept InterruptibleLock = Lockable<T> && requires(T t) {
  { t.InterruptibleLock() } -> std::same_as<bool>;
};

// LockAndParkable is the concept of a lock that can park and wait for a
// condition after unlocking.
template <typename T>
concept ParkableLock = Lockable<T> && requires(T t) {
  { t.UnlockAndPark() } -> std::same_as<void>;
};

// SharedLockable is the concept of a shared lock.
template <typename T>
concept SharedLockable = requires(T t) {
  { t.LockShared() } -> std::same_as<void>;
  { t.UnlockShared() } -> std::same_as<void>;
  { t.IsHeld() } -> std::same_as<bool>;
};

// TryableSharedLock is the concept of a lock that can tried to be acquired if
// not held already by a writer.
template <typename T>
concept TryableSharedLock = SharedLockable<T> && requires(T t) {
  { t.TryLockShared() } -> std::same_as<bool>;
};

// InterruptibleSharedLock is the concept of a shared lock that can be
// interrupted while waiting to be acquired.
template <typename T>
concept InterruptibleSharedLock = SharedLockable<T> && requires(T t) {
  { t.InterruptibleLockShared() } -> std::same_as<bool>;
};

// Wakable is a concept a blocking object that can be woken up
template <typename T>
concept Wakeable = requires(T t, thread_t *th) {
  { t.Arm(th) } -> std::same_as<void>;
  { t.Disarm(th) } -> std::same_as<bool>;
  { t.WakeThread(th) } -> std::same_as<bool>;
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
  // Works whether SetInterruptible() was called or not.
  interruptible_wake(th);
}

// ScopedLock releases a lock using RAII like std::scoped_lock.
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

 private:
  L &lock_;
};

// ScopedSharedLock releases a shared lock using RAII like std::scoped_lock.
template <SharedLockable L>
class ScopedSharedLock {
 public:
  [[nodiscard]] explicit ScopedSharedLock(L &lock) noexcept : lock_(lock) {
    lock_.LockShared();
  }
  ~ScopedSharedLock() { lock_.UnlockShared(); }

  ScopedSharedLock(ScopedSharedLock &&) = delete;
  ScopedSharedLock &operator=(ScopedSharedLock &&) = delete;
  ScopedSharedLock(const ScopedSharedLock &) = delete;
  ScopedSharedLock &operator=(const ScopedSharedLock &) = delete;

 private:
  L &lock_;
};

struct defer_lock_t {
  explicit defer_lock_t() = default;
};
struct adopt_lock_t {
  explicit adopt_lock_t() = default;
};
struct try_to_lock_t {
  explicit try_to_lock_t() = default;
};
struct interrupt_or_lock_t {
  explicit interrupt_or_lock_t() = default;
};

// Don't take the lock.
inline constexpr defer_lock_t DeferLock{};
// Adopt the lock in an already locked state.
inline constexpr adopt_lock_t AdoptLock{};
// Acquire the lock only if it is uncontended.
inline constexpr try_to_lock_t TryToLock{};
// Acquire the lock only if a signal is not pending.
inline constexpr interrupt_or_lock_t InterruptOrLock{};

// UniqueLock provides ownership of a lock object similar to std::unique_lock.
template <Lockable L>
class UniqueLock {
 public:
  [[nodiscard]] UniqueLock() noexcept : lock_(nullptr), owns_(false) {}
  [[nodiscard]] explicit UniqueLock(L &lock) noexcept
      : lock_(&lock), owns_(true) {
    lock_->Lock();
  }
  [[nodiscard]] UniqueLock(L &lock, defer_lock_t t) noexcept
      : lock_(&lock), owns_(false) {}
  [[nodiscard]] UniqueLock(L &lock, adopt_lock_t t) noexcept
      : lock_(&lock), owns_(true) {
    assert(lock_->IsHeld());
  }
  [[nodiscard]] UniqueLock(L &lock, try_to_lock_t t) noexcept
    requires TryableLock<L>
      : lock_(&lock) {
    owns_ = lock_->TryLock();
  }
  [[nodiscard]] UniqueLock(L &lock, interrupt_or_lock_t t) noexcept
    requires InterruptibleLock<L>
      : lock_(&lock) {
    owns_ = lock_->InterruptibleLock();
  }
  ~UniqueLock() {
    if (owns_) lock_->Unlock();
  }

  // Allow move, disable copy
  UniqueLock(UniqueLock &&ul) noexcept
      : lock_(std::exchange(ul.lock_, nullptr)),
        owns_(std::exchange(ul.owns_, false)) {}
  UniqueLock &operator=(UniqueLock &&ul) noexcept {
    lock_ = std::exchange(ul.lock_, nullptr);
    owns_ = std::exchange(ul.owns_, false);
    return *this;
  }
  UniqueLock(const UniqueLock &) = delete;
  UniqueLock &operator=(const UniqueLock &) = delete;

  explicit operator bool() const noexcept { return owns_; }

  void Lock() {
    assert(lock_ && !owns_);
    lock_->Lock();
    owns_ = true;
  }

  [[nodiscard]] bool TryLock()
    requires TryableLock<L>
  {
    assert(lock_ && !owns_);
    owns_ = lock_->TryLock();
    return owns_;
  }

  [[nodiscard]] bool InterruptibleLock()
    requires InterruptibleLock<L>
  {
    assert(lock_ && !owns_);
    owns_ = lock_->InterruptibleLock();
    return owns_;
  }

  void Unlock() {
    assert(lock_ && owns_);
    lock_->Unlock();
    owns_ = false;
  }

  void UnlockAndPark()
    requires ParkableLock<L>
  {
    assert(lock_ && owns_);
    lock_->UnlockAndPark();
    owns_ = false;
  }

 private:
  L *lock_;
  bool owns_;
};

// SharedLock provides ownership of a shared lock object similar to
// std::shared_lock.
template <SharedLockable L>
class SharedLock {
 public:
  [[nodiscard]] SharedLock() noexcept : lock_(nullptr), owns_(false) {}
  [[nodiscard]] explicit SharedLock(L &lock) noexcept
      : lock_(&lock), owns_(true) {
    lock_->LockShared();
  }
  [[nodiscard]] SharedLock(L &lock, defer_lock_t t) noexcept
      : lock_(&lock), owns_(false) {
    assert(!lock_->IsHeld());
  }
  [[nodiscard]] SharedLock(L &lock, adopt_lock_t t) noexcept
      : lock_(&lock), owns_(true) {
    assert(lock_->IsHeld());
  }
  [[nodiscard]] SharedLock(L &lock, try_to_lock_t t) noexcept
    requires TryableSharedLock<L>
      : lock_(&lock) {
    owns_ = lock_->TryLockShared();
  }
  [[nodiscard]] SharedLock(L &lock, interrupt_or_lock_t t) noexcept
    requires InterruptibleSharedLock<L>
      : lock_(&lock) {
    owns_ = lock_->InterruptibleLockShared();
  }
  ~SharedLock() {
    if (owns_) lock_->UnlockShared();
  }

  // Allow move, disable copy
  SharedLock(SharedLock &&ul) noexcept
      : lock_(std::exchange(ul.lock_, nullptr)),
        owns_(std::exchange(ul.owns_, false)) {}
  SharedLock &operator=(SharedLock &&ul) noexcept {
    lock_ = std::exchange(ul.lock_, nullptr);
    owns_ = std::exchange(ul.owns_, false);
    return *this;
  }
  SharedLock(const SharedLock &) = delete;
  SharedLock &operator=(const SharedLock &) = delete;

  explicit operator bool() const noexcept { return owns_; }

  void Lock() {
    assert(lock_ && !owns_);
    lock_->LockShared();
    owns_ = true;
  }

  [[nodiscard]] bool TryLock()
    requires TryableLock<L>
  {
    assert(lock_ && !owns_);
    owns_ = lock_->TryLockShared();
    return owns_;
  }

  [[nodiscard]] bool InterruptibleLock()
    requires InterruptibleLock<L>
  {
    assert(lock_ && !owns_);
    owns_ = lock_->InterruptibleLockShared();
    return owns_;
  }

  void Unlock() {
    assert(lock_ && owns_);
    lock_->UnlockShared();
    owns_ = false;
  }

  UniqueLock<L> Upgrade() {
    assert(lock_ && owns_);
    lock_->UpgradeLock();
    owns_ = false;
    return UniqueLock<L>(*lock_, AdoptLock);
  }

 private:
  L *lock_;
  bool owns_;
};

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

  // Empty returns true if there are no armed threads.
  [[nodiscard]] bool Empty() const { return list_empty(&waiters_); }

  explicit operator bool() const noexcept { return !Empty(); }

  // Arm prepares the running thread to block. Can only be called once,
  // must be synchronized by caller.
  void Arm(thread_t *th = thread_self()) {
    assert(!th->link_armed);
    th->link_armed = true;
    list_add_tail(&waiters_, &th->interruptible_link);
  }

  // Disarm removes a thread; must be synchronized by caller.
  bool Disarm(thread_t *th) {
    if (!th->link_armed) return false;
    list_del_from(&waiters_, &th->interruptible_link);
    th->link_armed = false;
    return true;
  }

  // Wake up to one thread waiter (must be synchronized by caller)
  // Returns true if a waiter was found and removed from the list.
  bool WakeOne() {
    thread_t *th = list_pop(&waiters_, thread_t, interruptible_link);
    if (th == nullptr) return false;
    th->link_armed = false;
    ThreadReady(th);
    return true;
  }

  // Wake all thread waiters (must be synchronized by caller)
  bool WakeAll() {
    bool did_wakeup = false;
    while (true) {
      thread_t *th = list_pop(&waiters_, thread_t, interruptible_link);
      if (th == nullptr) return did_wakeup;
      th->link_armed = false;
      ThreadReady(th);
      did_wakeup = true;
    }
  }

  // WakeThread makes a specific thread runnable. Returns true if woken.
  // Must be synchronized by caller.
  bool WakeThread(thread_t *th) {
    if (!th->link_armed) return false;
    list_del_from(&waiters_, &th->interruptible_link);
    th->link_armed = false;
    ThreadReady(th);
    return true;
  }

  // Pop removes a waiter without waking it, so it can be armed on a different
  // WaitQueue. Returns nullptr if there all no waiters.
  thread_t *Pop() {
    thread_t *th = list_pop(&waiters_, thread_t, interruptible_link);
    if (th) th->link_armed = false;
    return th;
  }

  // Splice moves all the waiters from another wait queue to this one.
  void Splice(WaitQueue &wq) { list_append_list(&waiters_, &wq.waiters_); }

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

  // Disarm cancels an armed thread; must be synchronized by caller.
  bool Disarm(thread_t *th) {
    assert(!th_ || th_ == th);
    return std::exchange(th_, nullptr) != nullptr;
  }

  // Wake makes the parked thread runnable. Must be called by another thread
  // after the prior thread has called Arm() and has parked (or will park in
  // the immediate future). Returns true if a thread was woken.
  bool Wake() {
    if (th_ == nullptr) return false;
    thread_t *th = std::exchange(th_, nullptr);
    ThreadReady(th);
    return true;
  }

  // WakeThread makes a specific thread runnable. In this class, it can only be
  // the parked thread. Returns true if the thread was woken.
  bool WakeThread(thread_t *th) {
    assert(!th_ || th_ == th);
    return Wake();
  }

  explicit operator bool() const noexcept { return th_ != nullptr; }

 private:
  thread_t *th_ = nullptr;
};

// Wait blocks the calling thread until a wakable object resumes it.
//
// A lock must be held to protect the wakeup condition state, which usually
// includes the wakable object.
template <ParkableLock L, Wakeable W>
void Wait(L &lock, W &waker) {
  assert(lock.IsHeld());
  waker.Arm();
  lock.UnlockAndPark();
  lock.Lock();
}

// Wait blocks the calling thread until the predicate becomes true
//
// A lock must be held to protect the wakeup condition state, which usually
// includes the wakable object.
template <ParkableLock L, Wakeable Waker, typename Predicate>
void Wait(L &lock, Waker &waker, Predicate stop) {
  while (!stop()) Wait(lock, waker);
}

// WaitNoRecheck blocks the calling thread until a wakable object resumes it.
//
// In this variant, the lock must be moved by the caller and will not
// reacquired after wakeup. This can be used as an optimization if the
// programmer is sure there will never be spurious wakeups and no condition has
// to be rechecked upon wakeup.
template <ParkableLock L, Wakeable W>
void WaitNoRecheck(UniqueLock<L> &&lock, W &waker) {
  assert(!!lock);
  waker.Arm();
  lock.UnlockAndPark();
}

// WaitInterruptible blocks the calling thread until a wakable object resumes it
// or a signal is delivered.
//
// A lock must be held to protect the wakeup condition state, which must
// include the wakable object.
//
// Returns true if woke up normally (not interrupted by a signal).
template <ParkableLock L, Wakeable Waker>
bool WaitInterruptible(L &lock, Waker &waker) {
  assert(lock.IsHeld());

  // Block and wait for an event.
  thread_t *th = thread_self();
  if (unlikely(SetInterruptible(th))) return false;
  waker.Arm(th);
  lock.UnlockAndPark();
  lock.Lock();
  // If the waker is still armed, a signal woke us up.
  return !waker.Disarm(th);
}

// WaitInterruptible blocks the calling thread until the predicate becomes true
// or a signal is delivered.
//
// A lock must be held to protect the wakeup condition state, which must
// include the wakable object.
//
// Returns true if woke up normally (not interrupted by a signal).
template <ParkableLock L, Wakeable Waker, typename Predicate>
bool WaitInterruptible(L &lock, Waker &w, Predicate stop) {
  while (!stop()) {
    if (unlikely(!WaitInterruptible(lock, w))) return false;
  }
  return true;
}

// WaitInterruptibleNoRecheck blocks the calling thread until a wakable object
// resumes it or a signal is delivered.
//
// A lock must be held to protect the wakeup condition state, which must
// include the wakable object.
//
// In this variant, the lock must be moved by the caller and will not
// reacquired after wakeup. This can be used as an optimization if the
// programmer is sure there will never be spurious wakeups and no condition has
// to be rechecked upon wakeup.
//
// Returns true if woke up normally (not interrupted by a signal).
template <ParkableLock L, Wakeable Waker>
bool WaitInterruptibleNoRecheck(UniqueLock<L> &&lock, Waker &waker) {
  assert(!!lock);

  // Block and wait for an event.
  thread_t *th = thread_self();
  if (unlikely(SetInterruptible(th))) return false;
  waker.Arm(th);
  lock.UnlockAndPark();

  // Check if a signal was delivered while blocked.
  if (unlikely(GetInterruptibleStatus(th) != InterruptibleStatus::kNone)) {
    // If a signal was delivered, use lock to synchronize with waker thread to
    // ensure that the waker object is disarmed before returning.
    lock.Lock();
    // A signal delivery may race with a normal wake. If the waker is already
    // disarmed, then a regular wake has already occured.
    return !waker.Disarm(th);
  }

  return true;
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

class Mutex {
 public:
  friend class ConditionVariable;

  Mutex() noexcept = default;
  ~Mutex() { assert(!IsHeld()); }

  // disable copy and move
  Mutex(const Mutex &) = delete;
  Mutex &operator=(const Mutex &) = delete;
  Mutex(Mutex &&) = delete;
  Mutex &operator=(Mutex &&) = delete;

  // Lock acquires the lock.
  void Lock();

  // TryLock acquires the lock if not held. Returns true if acquired.
  [[nodiscard]] bool TryLock();

  // InterruptibleLock acquires the lock if a signal is not pending. Returns
  // true if acquired.
  [[nodiscard]] bool InterruptibleLock();

  // Unlock releases the mutex.
  void Unlock();

  // IsHeld() returns true if the lock is held.
  [[nodiscard]] bool IsHeld() const { return held_; }

 private:
  Spin lock_;
  bool held_{false};
  WaitQueue queue_;
};

class SharedMutex {
 public:
  SharedMutex() noexcept = default;
  ~SharedMutex() { assert(!IsHeld()); }

  // disable copy and move
  SharedMutex(const SharedMutex &) = delete;
  SharedMutex &operator=(const SharedMutex &) = delete;
  SharedMutex(SharedMutex &&) = delete;
  SharedMutex &operator=(SharedMutex &&) = delete;

  // IsHeld() returns true if the lock is held.
  [[nodiscard]] bool IsHeld() const { return cnt_ != 0; }

  // IsHeldShared() returns true if the lock is held in shared mode.
  [[nodiscard]] bool IsHeldShared() const { return cnt_ > 0; }

  // IsHeldExclusive() returns true if the lock is held in exlusive mode.
  [[nodiscard]] bool IsHeldExclusive() const { return cnt_ < 0; }

  //
  // Exclusive (writer) lock API
  //

  // Lock acquires the lock as a writer.
  void Lock();

  // TryLock acquires the lock as a writer if not held by readers or a writer.
  // Returns true if acquired.
  [[nodiscard]] bool TryLock();

  // InterruptibleLock acquires the lock if a signal is not pending. Returns
  // true if acquired.
  [[nodiscard]] bool InterruptibleLock();

  // Unlock releases the mutex as a writer.
  void Unlock();

  //
  // Shared (reader) lock API
  //

  // LockShared acquires the lock as a reader.
  void LockShared();

  // TryLockShared acquires the lock as a reader if not held by a writer.
  // Returns true if acquired.
  [[nodiscard]] bool TryLockShared();

  // InterruptibleLockShared acquires the lock as a reader if a signal is not
  // pending. Returns true if acquired.
  [[nodiscard]] bool InterruptibleLockShared();

  // UnlockShared releases the mutex as a reader.
  void UnlockShared();

  // Upgrade a reader to a writer. Another writer may obtain the lock before
  // this call returns, so the caller should assume that the protected data may
  // have been modified during this call.
  void UpgradeLock();

  // Downgrade a writer to a reader without dropping the lock (no writer will be
  // scheduled until at least after the reader lock is released.
  void DowngradeLock();

 private:
  void WakeAllShared(WaitQueue &dst);
  void WakeOneExclusive(WaitQueue &dst);

  Spin lock_;
  int cnt_{0};         // >0 for # of readers, 0 for unlocked, -1 for a writer
  int shared_cnt_{0};  // number of entries in the shared_queue_
  WaitQueue exclusive_queue_;
  WaitQueue shared_queue_;
};

// forward declaration
template <Wakeable T>
class WakeOnTimeout;

class ConditionVariable {
 public:
  ConditionVariable() noexcept = default;
  ~ConditionVariable() = default;

  // disable move and copy
  ConditionVariable(ConditionVariable &&) = delete;
  ConditionVariable &operator=(ConditionVariable &&) = delete;
  ConditionVariable(const ConditionVariable &) = delete;
  ConditionVariable &operator=(const ConditionVariable &) = delete;

  // Wait blocks until the condition variable is notified.
  // The condition should be rechecked after wakeup.
  void Wait(Mutex &mu);

  // WaitFor blocks until the condition variable is notified or the duration
  // has elapsed. Returns true if notified (not a timeout).
  // The condition should be rechecked after wakeup.
  [[nodiscard]] bool WaitFor(Mutex &mu, Duration d);

  // WaitUntil blocks until the condition variable is notified or a timepoint
  // is reached. Returns true if notified (not a timeout).
  // The condition should be rechecked after wakeup.
  [[nodiscard]] bool WaitUntil(Mutex &mu, Time t);

  // WaitInterruptible blocks until the condition variable is notified or a
  // signal is pending. Returns true if notified (not a signal pending).
  // The condition should be rechecked after wakeup.
  [[nodiscard]] bool WaitInterruptible(Mutex &mu);

  // WaitInterruptibleFor blocks until the condition variable is notified or the
  // duration has elapsed. Returns EINTR if interrupted, ETIMEDOUT if timed out,
  // otherwise success. The condition should be rechecked after wakeup.
  Status<void> WaitInterruptibleFor(Mutex &mu, Duration d);

  // WaitInterruptibleUntil blocks until the condition variable is notified or a
  // timepoint is reached. Returns EINTR if interrupted, ETIMEDOUT if timed out,
  // otherwise success. The condition should be rechecked after wakeup.
  Status<void> WaitInterruptibleUntil(Mutex &mu, Time t);

  //
  // predicate variants of the above
  //
  template <typename Predicate>
  void Wait(Mutex &mu, Predicate stop) {
    while (!stop()) Wait(mu);
  }
  template <typename Predicate>
  bool WaitFor(Mutex &mu, Duration d, Predicate stop) {
    while (!stop()) {
      if (!WaitFor(mu, d)) return false;
    }
    return true;
  }
  template <typename Predicate>
  bool WaitUntil(Mutex &mu, Time t, Predicate stop) {
    while (!stop()) {
      if (!WaitUntil(mu, t)) return false;
    }
    return true;
  }
  template <typename Predicate>
  bool WaitInterruptible(Mutex &mu, Predicate stop) {
    while (!stop()) {
      if (!WaitInterruptible(mu)) return false;
    }
    return true;
  }
  template <typename Predicate>
  Status<void> WaitInterruptibleFor(Mutex &mu, Duration d, Predicate stop) {
    while (!stop()) {
      Status<void> ret = WaitInterruptibleFor(mu, d);
      if (!ret) return MakeError(ret);
    }
    return {};
  }
  template <typename Predicate>
  Status<void> WaitInterruptibleUntil(Mutex &mu, Time t, Predicate stop) {
    while (!stop()) {
      Status<void> ret = WaitInterruptibleUntil(mu, t);
      if (!ret) return MakeError(ret);
    }
    return {};
  }

  // Notify wakes one waiter.
  void Notify();

  // NotifyAll walkes all waiters.
  void NotifyAll();

 private:
  bool DoWait(bool block, const bool *timeout = nullptr);
  auto TimeoutHandler(bool &timeout) {
    timeout = false;
    return [this, &timeout, th = thread_self()]() {
      ScopedLock g(lock_->lock_);
      // Try to disarm; if already disarmed, the thread woke before the timeout.
      if (!queue_.Disarm(th)) return;

      // Try to reacquire the mutex and wake the thread if not held.
      timeout = true;
      if (lock_->held_) {
        lock_->queue_.Arm(th);
        return;
      }
      lock_->held_ = true;
      ThreadReady(th);
    };
  }

  WaitQueue queue_;
  Mutex *lock_{nullptr};
};

// Latch provides a barrier abstraction similar to std::latch. A latch cannot
// be reused after its countdown has reached zero.
class Latch {
 public:
  explicit Latch(int count) noexcept : cnt_(count) {}
  ~Latch() = default;

  // disable move and copy
  Latch(Latch &&) = delete;
  Latch &operator=(Latch &&) = delete;
  Latch(const Latch &) = delete;
  Latch &operator=(const Latch &) = delete;

  // CountDown decrements the counter by @count and wakes the waiters if zero
  // is reached.
  void CountDown(int count);

  // TryWait returns true if the internal counter has reached zero.
  [[nodiscard]] bool TryWait();

  // Wait blocks until the internal counter reaches zero.
  void Wait();

  // ArriveAndWait decrements the internal counter by @count and blocks until
  // it reaches zero.
  void ArriveAndWait(int count = 1);

  // WaitInterruptible blocks until the internal counter reaches zero. Returns
  // true if not interrupted by a signal.
  [[nodiscard]] bool WaitInterruptible();

  // ArriveAndWaitInterruptible decrements the internal counter by @count and
  // blocks until it reaches zero. Returns true if not interrupted by a signal.
  [[nodiscard]] bool ArriveAndWaitInterruptible(int count = 1);

  // POSIXWaitInterruptible provides the same behavior as
  // ArriveAndWaitInterruptible with @count = 1. In addition, @serial_thread
  // is set to true for exactly one waiting thread. This variant should not be
  // used normally, but it is provided as a building block for supporting POSIX
  // barriers (which need to identify the serial thread). Returns true if not
  // interrupted by a signal.
  [[nodiscard]] bool POSIXWaitInterruptible(bool *serial_thread = nullptr);

 private:
  Spin lock_;
  int cnt_;
  WaitQueue queue_;
};

// WaitForever blocks the thread forever (doesn't return).
inline void WaitForever() {
  Preempt::Lock();
  Preempt::UnlockAndPark();
}

// Convenient shorthands
using SpinGuard = ScopedLock<Spin>;
using MutexGuard = ScopedLock<Mutex>;
using PreemptGuard = ScopedLock<Preempt>;
using SharedMutexGuard = ScopedSharedLock<SharedMutex>;

}  // namespace junction::rt
