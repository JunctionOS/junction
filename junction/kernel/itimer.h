#pragma once

#include <time.h>

#include <memory>

#include "junction/bindings/log.h"
#include "junction/bindings/timer.h"
#include "junction/snapshot/proc.h"

namespace junction {

class Process;

class ITimer : private rt::timer_internal::timer_node {
 public:
  explicit ITimer(Process &proc) : proc_(proc) {
    auto arg = reinterpret_cast<unsigned long>(static_cast<timer_node *>(this));
    timer_init(&entry_, rt::timer_internal::TimerTrampoline, arg);
  }

  ~ITimer() { timer_cancel_recurring(&entry_); }

  itimerval get() const {
    Duration d = next_fire_ ? Duration::Until(*next_fire_) : Duration(0);
    return {interval_.Timeval(), d.Timeval()};
  }

  itimerval exchange(const itimerval &it) {
    // synchronize with the timer callback
    timer_cancel_recurring(&entry_);

    itimerval old = get();

    // record new interval
    interval_ = Duration(it.it_interval);

    // check if we need to start the timer
    Duration d(it.it_value);
    if (d.IsZero()) {
      next_fire_ = std::nullopt;
    } else {
      next_fire_ = Time::Now() + d;
      timer_start(&entry_, next_fire_->Microseconds());
    }

    return old;
  }

  void Snapshot(ProcessMetadata &s) const &;

  // disable copy and move.
  ITimer(const ITimer &) = delete;
  ITimer &operator=(const ITimer &) = delete;
  ITimer(const ITimer &&) = delete;
  ITimer &operator=(const ITimer &&) = delete;

 private:
  void Run() override;
  timer_entry entry_;
  Duration interval_{0};
  std::optional<Time> next_fire_{std::nullopt};
  Process &proc_;
};

}  // namespace junction
