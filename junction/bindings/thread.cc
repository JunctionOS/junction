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
  if (d->done.load(std::memory_order_acquire)) {
    d->waker.Wake();
    return;
  }

  // Cold path: Check again with the lock held.
  d->lock.Lock();
  if (d->done.load(std::memory_order_relaxed)) {
    d->waker.Wake();
    d->lock.Unlock();
    return;
  }
  d->waker.Arm();
  d->done.store(true, std::memory_order_release);
  d->lock.UnlockAndPark();
}

}  // namespace thread_internal

void Thread::Detach() {
  assert(join_data_ != nullptr);
  auto* d = join_data_;
  auto f = finally([this] { join_data_ = nullptr; });

  // Hot path if the thread is already blocked.
  if (d->done.load(std::memory_order_acquire)) {
    d->waker.Wake();
    return;
  }

  // Cold path: The thread is not yet blocked.
  {
    rt::SpinGuard g(d->lock);
    if (d->done.load(std::memory_order_relaxed)) {
      d->waker.Wake();
      return;
    }
    d->done.store(true, std::memory_order_release);
  }
}

void Thread::Join() {
  assert(join_data_ != nullptr);
  auto* d = join_data_;
  auto f = finally([this] { join_data_ = nullptr; });

  // Hot path if the thread is already blocked.
  if (d->done.load(std::memory_order_acquire)) {
    d->waker.Wake();
    return;
  }

  // Cold path: The thread is not yet blocked.
  d->lock.Lock();
  if (d->done.load(std::memory_order_relaxed)) {
    d->lock.Unlock();
    d->waker.Wake();
    return;
  }
  d->waker.Arm();
  d->done.store(true, std::memory_order_release);
  d->lock.UnlockAndPark();
}

}  // namespace junction::rt
