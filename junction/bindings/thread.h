// thread.h - Support for creating and managing threads

#pragma once

extern "C" {
#include <base/assert.h>
#include <runtime/sync.h>
}

#include <functional>

namespace junction::rt {
namespace thread_internal {

struct join_data {
  join_data(std::function<void()>&& func) noexcept
      : done_(false), waiter_(nullptr), func_(std::move(func)) {
    spin_lock_init(&lock_);
  }
  join_data(const std::function<void()>& func) noexcept
      : done_(false), waiter_(nullptr), func_(func) {
    spin_lock_init(&lock_);
  }

  spinlock_t lock_;
  bool done_;
  thread_t* waiter_;
  std::function<void()> func_;
};

extern void ThreadTrampoline(void* arg);
extern void ThreadTrampolineWithJoin(void* arg);

}  // namespace thread_internal

// Spawns a new thread by copying.
inline void Spawn(const std::function<void()>& func) {
  void* buf;
  thread_t* th = thread_create_with_buf(thread_internal::ThreadTrampoline, &buf,
                                        sizeof(std::function<void()>));
  if (unlikely(!th)) BUG();
  new (buf) std::function<void()>(func);
  thread_ready(th);
}

// Spawns a new thread by moving.
inline void Spawn(std::function<void()>&& func) {
  void* buf;
  thread_t* th = thread_create_with_buf(thread_internal::ThreadTrampoline, &buf,
                                        sizeof(std::function<void()>));
  if (unlikely(!th)) BUG();
  new (buf) std::function<void()>(std::move(func));
  thread_ready(th);
}

// Called from a running thread to exit.
inline void Exit() { thread_exit(); }

// Called from a running thread to yield.
inline void Yield() { thread_yield(); }

// An STL-style thread class
class Thread {
 public:
  // boilerplate constructors.
  Thread() noexcept : join_data_(nullptr) {}
  ~Thread() { assert(join_data_ == nullptr); }

  // disable copy.
  Thread(const Thread&) = delete;
  Thread& operator=(const Thread&) = delete;

  // Move support.
  Thread(Thread&& t) noexcept : join_data_(t.join_data_) {
    t.join_data_ = nullptr;
  }
  Thread& operator=(Thread&& t) noexcept {
    join_data_ = t.join_data_;
    t.join_data_ = nullptr;
    return *this;
  }

  // Spawns a thread by copying a std::function.
  Thread(const std::function<void()>& func);

  // Spawns a thread by moving a std::function.
  Thread(std::function<void()>&& func);

  // Waits for the thread to exit.
  void Join();

  // Detaches the thread, indicating it won't be joined in the future.
  void Detach();

 private:
  thread_internal::join_data* join_data_;
};

}  // namespace junction::rt
