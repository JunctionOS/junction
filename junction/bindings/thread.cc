#include "junction/bindings/thread.h"

#include <memory>

namespace junction::rt {
namespace thread_internal {

// A helper to jump from extern C back to C++ for rt::Spawn().
void ThreadTrampoline(void* arg) {
  auto* wrapper = static_cast<WrapperBase*>(arg);
  wrapper->Run();
  std::destroy_at(wrapper);
}

// A helper to jump from extern C back to C++ for Thread::Thread().
void ThreadTrampolineWithJoin(void* arg) {
  auto* d = static_cast<join_data*>(arg);
  d->Run();
  spin_lock_np(&d->lock_);
  if (d->done_) {
    spin_unlock_np(&d->lock_);
    if (d->waiter_) thread_ready(d->waiter_);
    std::destroy_at(d);
    return;
  }
  d->done_ = true;
  d->waiter_ = thread_self();
  thread_park_and_unlock_np(&d->lock_);
  std::destroy_at(d);
}

}  // namespace thread_internal

void Thread::Detach() {
  assert(join_data_ != nullptr);

  spin_lock_np(&join_data_->lock_);
  if (join_data_->done_) {
    spin_unlock_np(&join_data_->lock_);
    assert(join_data_->waiter_ != nullptr);
    thread_ready(join_data_->waiter_);
    join_data_ = nullptr;
    return;
  }

  join_data_->done_ = true;
  join_data_->waiter_ = nullptr;
  spin_unlock_np(&join_data_->lock_);
  join_data_ = nullptr;
}

void Thread::Join() {
  assert(join_data_ != nullptr);

  spin_lock_np(&join_data_->lock_);
  if (join_data_->done_) {
    spin_unlock_np(&join_data_->lock_);
    assert(join_data_->waiter_ != nullptr);
    thread_ready(join_data_->waiter_);
    join_data_ = nullptr;
    return;
  }

  join_data_->done_ = true;
  join_data_->waiter_ = thread_self();
  thread_park_and_unlock_np(&join_data_->lock_);
  join_data_ = nullptr;
}

}  // namespace junction::rt
