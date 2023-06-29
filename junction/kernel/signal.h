// signal.h - support for signal handling

#pragma once

extern "C" {
#include <signal.h>
}

namespace junction {

namespace detail {

struct signal_entry {
  struct sigaction saction;
  stack_t sstack;
};

}  // namespace detail

// The maximum number of signals supported.
inline constexpr int kNumSignals = 32;

class SignalTable {
 public:
  SignalTable() : table_() {};
  ~SignalTable() = default;

  [[nodiscard]] struct sigaction get_action(int sig) {
    assert(sig > 0 && sig < kNumSignals);
    return table_[sig].saction;
  }
  [[nodiscard]] stack_t get_stack(int sig) {
    assert(sig > 0 && sig < kNumSignals);
    return table_[sig].sstack;
  }

  void set_action(int sig, struct sigaction sa) {
    assert(sig > 0 && sig < kNumSignals);
    table_[sig].saction = sa;
  }
  void set_action(int sig, stack_t stack) {
    assert(sig > 0 && sig < kNumSignals);
    table_[sig].sstack = stack;
  }

 private:
  detail::signal_entry table_[kNumSignals];
};

}  // namespace junction
