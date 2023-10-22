// signal.h - support for signal handling

#pragma once

extern "C" {
#include <signal.h>
}

#include <list>

#include "junction/kernel/sigframe.h"

namespace junction {

typedef uint64_t k_sigset_t;
typedef void (*sighandler)(int sig, siginfo_t *info, void *uc);

// The maximum number of signals.
inline constexpr int kNumSignals = 64;
// The maximum number of standard signals (defined in POSIX).
inline constexpr int kNumStandardSignals = 32;
// If set as the handler, the default action will be performed.
inline constexpr sighandler kDefaultHandler = nullptr;
static_assert(SIG_DFL == nullptr);

// SignalValid returns true if the signal number is valid.
inline constexpr bool SignalValid(int sig) {
  return sig > 0 && sig <= kNumSignals;
}

// Assertion for valid signal
inline void assert_signal_valid(int sig) { assert(SignalValid(sig)); }

// SignalMask converts a signal number to a mask with the signal's bit set.
inline constexpr k_sigset_t SignalMask(int sig) { return 1UL << (sig - 1); }

// SignalInMask returns true if the signal number is in the mask.
inline constexpr bool SignalInMask(k_sigset_t mask, int sig) {
  return (mask & SignalMask(sig)) > 0;
}

// KernelSigset converts a user sigset to the kernel's representation.
inline std::optional<k_sigset_t> KernelSigset(const sigset_t *usig) {
  if (!usig) return std::nullopt;
  return *reinterpret_cast<const k_sigset_t *>(usig);
}

// k_sigaction defines the actions for a signal (in sync with Linux definition)
struct k_sigaction {
  sighandler handler;
  unsigned long sa_flags;
  void (*restorer)(void);
  k_sigset_t sa_mask;

  [[nodiscard]] bool wants_altstack() const {
    return (sa_flags & SA_ONSTACK) > 0;
  }
  [[nodiscard]] bool is_oneshot() const {
    return (sa_flags & SA_RESETHAND) > 0;
  }
  [[nodiscard]] bool is_nodefer() const { return (sa_flags & SA_NODEFER) > 0; }

  void reset() {
    handler = kDefaultHandler;
    sa_flags = 0;
  }
};

class SignalQueue : public rt::Spin {
 public:
  SignalQueue() = default;
  ~SignalQueue() = default;

  template <typename Filter>
  std::optional<siginfo_t> GetSignal(k_sigset_t blocked, Filter f,
                                     bool remove) {
    int signo = __builtin_ffsl(pending_ & ~blocked);
    if (signo <= 0) return std::nullopt;

    siginfo_t si;
    si.si_signo = 0;
    size_t signo_count = 0;

    for (auto p = pending_q_.begin(); p != pending_q_.end();) {
      if (p->si_signo != signo) {
        p++;
        continue;
      }

      signo_count++;

      if (!si.si_signo && f(*p)) {
        if (!remove) return *p;
        si = *p;
        p = pending_q_.erase(p);
      }

      if (si.si_signo && signo_count > 1) break;
    }

    if (!si.si_signo) return std::nullopt;
    if (signo_count == 1) clear_sig_pending(signo);
    return si;
  }

  // Pop next queued signal from pending_q_
  siginfo_t PopNextSignal(k_sigset_t mask);
  // Enqueue a new signal, returns true if successful
  bool Enqueue(siginfo_t *info);

  [[nodiscard]] k_sigset_t get_pending() const { return access_once(pending_); }
  [[nodiscard]] bool is_sig_pending(int signo) const {
    return SignalInMask(get_pending(), signo);
  }

 private:
  void set_sig_pending(int signo) { pending_ |= SignalMask(signo); }
  void clear_sig_pending(int signo) { pending_ &= ~SignalMask(signo); }

  std::list<siginfo_t> pending_q_;
  k_sigset_t pending_{0};
};

class ThreadSignalHandler {
 public:
  ThreadSignalHandler(Process *proc) : proc_(proc){};
  ~ThreadSignalHandler() = default;

  [[nodiscard]] k_sigset_t get_pending() const;

  [[nodiscard]] bool any_sig_pending() const {
    return (get_pending() & ~access_once(blocked_)) > 0;
  }

  [[nodiscard]] bool is_sig_pending(int signo) const {
    return SignalInMask(get_pending(), signo);
  }

  [[nodiscard]] bool is_sig_blocked(int signo) const {
    return SignalInMask(access_once(blocked_), signo);
  }

  [[nodiscard]] bool has_altstack() const {
    return (sigaltstack_.ss_flags & SS_DISABLE) == 0;
  }

  [[nodiscard]] const stack_t &get_altstack() const { return sigaltstack_; }
  [[nodiscard]] k_sigset_t get_blocked_mask() const { return blocked_; }

  [[nodiscard]] k_sigset_t get_blocked_pending() const {
    return get_pending() & access_once(blocked_);
  }

  void DisableAltStack() {
    sigaltstack_.ss_flags = SS_DISABLE;
    thread_self()->tlsvar = 1;
  }

  Status<void> SigAltStack(const stack_t *ss, stack_t *old_ss) {
    if (old_ss) *old_ss = sigaltstack_;
    if (ss) sigaltstack_ = *ss;
    return {};
  }

  // Update blocked signal mask
  Status<void> SigProcMask(int how, const unsigned long *nset,
                           unsigned long *oset) {
    if (oset) *oset = blocked_;
    if (!nset) return {};

    switch (how) {
      case SIG_BLOCK:
        blocked_ |= *nset;
        break;
      case SIG_UNBLOCK:
        blocked_ &= ~(*nset);
        break;
      case SIG_SETMASK:
        blocked_ = *nset;
        break;
      default:
        return MakeError(EINVAL);
    }

    return {};
  }

  // Add a queued signal. Returns true if signal is queued and not blocked.
  bool EnqueueSignal(siginfo_t *info) {
    rt::SpinGuard g(sig_q_);
    // TODO: this check for blocked signals is racy and likely needs to be
    // fixed.
    return sig_q_.Enqueue(info) && !is_sig_blocked(info->si_signo);
  }

  // Called by this thread when in syscall context to run any pending signals
  // rax is provided if this is called after a syscall finishes before returning
  // to userspace. This function may not return.
  void RunPending(std::optional<long> rax);

  // Entry point for a kernel delivered signal.
  void DeliverKernelSigToUser(int signo, siginfo_t *info, k_sigframe *sigframe);

  // Save and restore blocked mask for system calls that manipulate the mask
  void SaveBlocked() { saved_blocked_ = blocked_; }
  void RestoreBlocked() {
    if (!saved_blocked_) return;
    blocked_ = *saved_blocked_;
    saved_blocked_ = std::nullopt;
  }

 private:
  // Check if signal can be delivered, and returns the action if so.
  // May modifies the sigaction if it is set to SA_ONESHOT
  std::optional<k_sigaction> GetAction(int signo);

  // Update a Linux sigframe with correct altstack, blocked mask, and restorer
  void TransformSigFrame(k_sigframe &sigframe, const k_sigaction &act) const;

  // @sig_q_ lock used to synchronize blocked signals
  SignalQueue sig_q_;
  k_sigset_t blocked_{0};
  std::optional<k_sigset_t> saved_blocked_;
  stack_t sigaltstack_{nullptr, SS_DISABLE, 0};
  Process *proc_;

  void set_sig_blocked(int signo) { blocked_ |= SignalMask(signo); }
  void clear_sig_blocked(int signo) { blocked_ &= ~SignalMask(signo); }
};

// SignalTable is a table of the signal actions for a process.
class alignas(kCacheLineSize) SignalTable {
 public:
  SignalTable() = default;
  ~SignalTable() = default;

  // get_action gets an action for a signal (resetting if one shot).
  [[nodiscard]] k_sigaction get_action(int sig, bool reset = false) {
    assert_signal_valid(sig);

    rt::SpinGuard g(lock_);
    k_sigaction sa = table_[sig - 1];
    if (reset && sa.is_oneshot()) table_[sig - 1].reset();
    return sa;
  }

  // exchange_action sets a new action for a signal and returns the old one.
  k_sigaction exchange_action(int sig, k_sigaction sa) {
    assert_signal_valid(sig);

    rt::SpinGuard g(lock_);
    return std::exchange(table_[sig - 1], sa);
  }

 private:
  rt::Spin lock_;  // protects @table_
  k_sigaction table_[kNumSignals]{};
};

Status<void> InitSignal();
extern "C" [[noreturn]] void usys_rt_sigreturn(uint64_t rsp);

}  // namespace junction
