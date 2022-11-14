#include "junction/bindings/thread.h"

#include <memory>

#include "junction/base/finally.h"

namespace junction::rt {
namespace thread_internal {

// A helper to jump from extern C back to C++ for rt::Spawn().
void ThreadTrampoline(void* arg) {
  auto* d = static_cast<basic_data*>(arg);
  d->Run();
  std::destroy_at(d);
}

// A helper to jump from extern C back to C++ for Thread::Thread().
void ThreadTrampolineWithJoin(void* arg) {
  auto* d = static_cast<join_data*>(arg);
  auto f = finally([d] { std::destroy_at(d); });
  d->Run();

  // Hot path if the thread is already detached or joined.
  if (d->done_.load(std::memory_order_acquire)) {
    d->waker_.Wake();
    return;
  }

  // Cold path: Check again with the lock held.
  d->lock_.Lock();
  if (d->done_.load(std::memory_order_relaxed)) {
    d->waker_.Wake();
    d->lock_.Unlock();
    return;
  }
  d->waker_.Arm();
  d->done_.store(true, std::memory_order_release);
  d->lock_.UnlockAndPark();
}

}  // namespace thread_internal

void Thread::Detach() {
  assert(join_data_ != nullptr);
  auto* d = join_data_;
  auto f = finally([this] { join_data_ = nullptr; });

  // Hot path if the thread is already blocked.
  if (d->done_.load(std::memory_order_acquire)) {
    d->waker_.Wake();
    return;
  }

  // Cold path: The thread is not yet blocked.
  {
    rt::SpinGuard g(&d->lock_);
    if (d->done_.load(std::memory_order_relaxed)) {
      d->waker_.Wake();
      return;
    }
    d->done_.store(true, std::memory_order_release);
  }
}

void Thread::Join() {
  assert(join_data_ != nullptr);
  auto* d = join_data_;
  auto f = finally([this] { join_data_ = nullptr; });

  // Hot path if the thread is already blocked.
  if (d->done_.load(std::memory_order_acquire)) {
    d->waker_.Wake();
    return;
  }

  // Cold path: The thread is not yet blocked.
  rt::SpinGuard g(&d->lock_);
  d->lock_.Lock();
  if (d->done_.load(std::memory_order_relaxed)) {
    d->lock_.Unlock();
    d->waker_.Wake();
    return;
  }
  d->waker_.Arm();
  d->done_.store(true, std::memory_order_release);
  d->lock_.UnlockAndPark();
}

}  // namespace junction::rt
