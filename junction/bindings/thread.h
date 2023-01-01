// thread.h - Support for creating and managing threads

#pragma once

extern "C" {
#include <base/assert.h>
#include <runtime/sync.h>
}

#include <atomic>
#include <concepts>
#include <functional>
#include <memory>
#include <type_traits>
#include <utility>

#include "junction/bindings/sync.h"

namespace junction::rt {
namespace thread_internal {

struct basic_data {
  virtual ~basic_data() = default;
  virtual void Run() = 0;
};

struct join_data {
  join_data() noexcept = default;
  virtual ~join_data() = default;
  virtual void Run() = 0;
  rt::Spin lock;
  rt::ThreadWaker waker;
  std::atomic_bool done{false};
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
  std::decay_t<Callable> func_;
  std::tuple<std::decay_t<Args>...> args_;
};

class AsyncBase {
 public:
  AsyncBase() = default;
  ~AsyncBase() = default;

  // Wake up any blocking future.
  void Notify() {
    done_.store(true, std::memory_order_release);
    rt::SpinGuard g(lock_);
    waker_.Wake();
  }

  // Block and waits (called by the future).
  void Wait() {
    // hot path
    if (done_.load(std::memory_order_acquire)) return;

    // slow path
    rt::SpinGuard g(lock_);
    g.Park(waker_, [this] { return done_.load(std::memory_order_relaxed); });
  }

 private:
  rt::Spin lock_;
  rt::ThreadWaker waker_;
  std::atomic_bool done_{false};
};

template <typename T>
struct async_state {
  void set_value(T&& value) {
    value_ = std::move(value);
    base_.Notify();
  }

  AsyncBase base_;
  T value_;
};

template <typename T>
struct async_state<T&> {
  void set_value(T& value) {
    value_ = value;
    base_.Notify();
  }

  AsyncBase base_;
  T& value_;
};

template <>
struct async_state<void> {
  void set_value() { base_.Notify(); }

  AsyncBase base_;
};

template <typename Ret, typename Callable, typename... Args>
class AsyncWrapper : public basic_data {
 public:
  AsyncWrapper(async_state<Ret>* state, Callable&& func,
               Args&&... args) noexcept
      : state_(state),
        func_(std::forward<Callable>(func)),
        args_{std::forward<Args>(args)...} {}
  ~AsyncWrapper() override = default;

  void Run() override {
    if constexpr (std::is_void_v<Ret>) {
      std::apply(func_, args_);
      state_->set_value();
    } else {
      state_->set_value(std::apply(func_, args_));
    }
  }

 private:
  async_state<Ret>* state_;
  std::decay_t<Callable> func_;
  std::tuple<std::decay_t<Args>...> args_;
};

extern "C" void ThreadTrampoline(void* arg);
extern "C" void ThreadTrampolineWithJoin(void* arg);

template <typename Callable, typename... Args>
using ret_t =
    std::invoke_result_t<std::decay_t<Callable>, std::decay_t<Args>...>;

}  // namespace thread_internal

// Called from a running thread to exit.
inline void Exit() { thread_exit(); }

// Called from a running thread to yield.
inline void Yield() { thread_yield(); }

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

// This is a very stripped down version of std::future (used for Async only).
template <typename T>
class Future {
 public:
  template <typename Callable, typename... Args>
  friend auto Async(Callable&& func,
                    Args&&... args) requires std::invocable<Callable, Args...>;

  Future() noexcept = default;
  ~Future() {
    if (is_valid()) Wait();
  }

  // disable copy.
  Future(const Future&) = delete;
  Future& operator=(const Future&) = delete;

  // Move support.
  Future(Future&& t) noexcept : state_(std::move(t.state_)) {}
  Future& operator=(Future&& t) noexcept {
    state_ = std::move(t.state_);
    return *this;
  }

  // Gets the value of the future, blocking if it is not ready.
  T get() {
    Wait();
    static_assert(std::is_void_v<T> || std::is_object_v<T> ||
                  std::is_lvalue_reference_v<T>);
    if constexpr (std::is_void_v<T>) {
      return;
    } else if (std::is_object_v<T>) {
      return std::move(state_->value_);
    } else {  // lvalue reference
      return state_->value_;
    }
  }

  // Checks if the future is attached to a promised value.
  [[nodiscard]] bool is_valid() const { return !!state_; }

  // Blocks and waits for the future's value to be ready.
  void Wait() { state_->base_.Wait(); }

 private:
  explicit Future(std::unique_ptr<thread_internal::async_state<T>> ptr)
      : state_{std::move(ptr)} {}

  std::unique_ptr<thread_internal::async_state<T>> state_{};
};

// Spawns a new thread and provides its return value as a future.
template <typename Callable, typename... Args>
auto Async(Callable&& func,
           Args&&... args) requires std::invocable<Callable, Args...> {
  void* buf;
  using Ret = thread_internal::ret_t<Callable, Args...>;
  using Wrapper = thread_internal::AsyncWrapper<Ret, Callable, Args...>;
  thread_t* th = thread_create_with_buf(thread_internal::ThreadTrampoline, &buf,
                                        sizeof(Wrapper));
  if (unlikely(!th)) BUG();
  auto state = std::make_unique<thread_internal::async_state<Ret>>();
  new (buf) Wrapper(state.get(), std::forward<Callable>(func),
                    std::forward<Args>(args)...);
  thread_ready(th);
  return Future<Ret>(std::move(state));
}

// A RAII thread object, similar to a std::jthread.
class Thread {
 public:
  // boilerplate constructors.
  Thread() noexcept = default;
  ~Thread() {
    if (Joinable()) Join();
  }

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
