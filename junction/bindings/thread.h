// thread.h - Support for creating and managing threads

#pragma once

extern "C" {
#include <base/assert.h>
#include <runtime/sync.h>
}

#include <concepts>
#include <functional>

namespace junction::rt {
namespace thread_internal {

class basic_data {
 public:
  virtual ~basic_data() = default;
  virtual void Run() = 0;
};

struct join_data {
  join_data() noexcept { spin_lock_init(&lock_); }
  virtual ~join_data() = default;
  virtual void Run() = 0;
  spinlock_t lock_;
  bool done_{false};
  thread_t* waiter_{nullptr};
};

template <typename Data, typename Callable, typename... Args>
class Wrapper : public Data {
 public:
  Wrapper(Callable&& func, Args&&... args) noexcept
      : func_(std::forward<Callable>(func)),
        args_{std::forward<Args>(args)...} {}
  ~Wrapper() override = default;

  void Run() override { std::apply(func_, args_); }

 private:
  Callable func_;
  std::tuple<std::decay_t<Args>...> args_;
};

extern "C" void ThreadTrampoline(void* arg);
extern "C" void ThreadTrampolineWithJoin(void* arg);

}  // namespace thread_internal

// Spawns a new thread.
template <typename Callable, typename... Args>
void Spawn(Callable&& func,
           Args&&... args) requires std::invocable<Callable, Args...> {
  void* buf;
  using Data = thread_internal::basic_data;
  using Wrapper = thread_internal::Wrapper<Data, Callable, Args...>;
  thread_t* th = thread_create_with_buf(thread_internal::ThreadTrampoline, &buf,
                                        sizeof(Wrapper));
  if (unlikely(!th)) BUG();
  new (buf) Wrapper(std::forward<Callable>(func), std::forward<Args>(args)...);
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
  Thread() noexcept = default;
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

  // Spawns a thread that runs the callable with the supplied arguments.
  template <typename Callable, typename... Args>
  Thread(Callable&& func,
         Args&&... args) requires std::invocable<Callable, Args...>;

  // Can the thread be joined?
  [[nodiscard]] bool Joinable() const { return join_data_ != nullptr; }

  // Waits for the thread to exit.
  void Join();

  // Detaches the thread, indicating it won't be joined in the future.
  void Detach();

 private:
  thread_internal::join_data* join_data_{nullptr};
};

template <typename Callable, typename... Args>
inline Thread::Thread(Callable&& func, Args&&... args) requires
    std::invocable<Callable, Args...> {
  using Data = thread_internal::join_data;
  using Wrapper = thread_internal::Wrapper<Data, Callable, Args...>;
  Wrapper* buf;
  thread_t* th =
      thread_create_with_buf(thread_internal::ThreadTrampolineWithJoin,
                             reinterpret_cast<void**>(&buf), sizeof(*buf));
  if (unlikely(!th)) BUG();
  new (buf) Wrapper(std::forward<Callable>(func), std::forward<Args>(args)...);
  join_data_ = buf;
  thread_ready(th);
}

}  // namespace junction::rt
