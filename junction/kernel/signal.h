// signal.h - support for signal handling

#pragma once

extern "C" {
#include <signal.h>
#include <stdint.h>
}

#include <list>
#include <optional>

#include "junction/bindings/stack.h"
#include "junction/kernel/sigframe.h"
#include "junction/kernel/trapframe.h"

namespace junction {

class Thread;
class ThreadMetadata;
class ProcessMetadata;

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

// Disable the altstack after delivering the signal.
inline constexpr uint32_t kSigStackAutoDisarm = (1U << 31);

template <typename... Args>
constexpr k_sigset_t MultiSignalMask(Args... args) {
  k_sigset_t mask = 0;
  for (const auto a : {args...}) mask |= SignalMask(a);
  return mask;
}

// Mask of signals that can only be handling in the kernel.
constexpr k_sigset_t kSignalKernelOnlyMask = MultiSignalMask(SIGKILL, SIGSTOP);

constexpr k_sigset_t kProcessWideSignals =
    MultiSignalMask(SIGKILL, SIGSTOP, SIGCONT);

constexpr k_sigset_t kStopStartSignals = MultiSignalMask(SIGSTOP, SIGCONT);

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
  [[nodiscard]] bool is_restartsys() const {
    return (sa_flags & SA_RESTART) > 0;
  }

  void reset() {
    handler = kDefaultHandler;
    sa_flags = 0;
  }
};
class SignalQueue : public rt::Spin {
 public:
  SignalQueue() = default;
  ~SignalQueue() = default;

  // Pop a signal from this queue.
  std::optional<siginfo_t> Pop(k_sigset_t blocked, bool remove);

  // Enqueue a new signal, returns true if successful
  bool Enqueue(const siginfo_t &info);

  [[nodiscard]] k_sigset_t get_pending(k_sigset_t blocked = 0) const {
    return access_once(pending_) & ~blocked;
  }
  [[nodiscard]] bool is_sig_pending(int signo) const {
    return SignalInMask(get_pending(), signo);
  }

  void Snapshot(ProcessMetadata &) const &;
  void Snapshot(ThreadMetadata &) const &;
  void Restore(ProcessMetadata const &pm);
  void Restore(ThreadMetadata const &tm);

 private:
  void set_sig_pending(int signo) { pending_ |= SignalMask(signo); }
  void clear_sig_pending(int signo) { pending_ &= ~SignalMask(signo); }

 private:
  std::list<siginfo_t> pending_q_;
  k_sigset_t pending_{0};
};

struct DeliveredSignal {
  k_sigaction act;
  siginfo_t info;
  stack_t ss;
  k_sigset_t prev_blocked;

  // Fix a stack pointer based on the altstack configuration for this signal.
  [[nodiscard]] uint64_t FixRspAltstack(uint64_t rsp) const {
    // do nothing if this sigaction doesn't use an altstack
    if (!act.wants_altstack()) return rsp;

    // check if the altstack was valid
    if (ss.ss_flags & SS_DISABLE) return rsp;

    // check if we are already on the altsack
    if (IsOnStack(rsp, ss)) return rsp;

    // switch to the altstack
    return reinterpret_cast<uint64_t>(ss.ss_sp) + ss.ss_size;
  }
};

class ThreadSignalHandler {
 public:
  ThreadSignalHandler(Thread &thread);
  ~ThreadSignalHandler() = default;

  // Get the set of pending signals (both for this thread and the whole process)
  [[nodiscard]] k_sigset_t get_any_pending() const {
    return sig_q_.get_pending() | shared_q_.get_pending();
  }

  // Check if any pending signal can be delivered.
  [[nodiscard]] bool any_sig_ready() const {
    return (get_any_pending() & ~blocked_) != 0;
  }

  [[nodiscard]] bool is_sig_pending(int signo) const {
    return SignalInMask(get_any_pending(), signo);
  }

  [[nodiscard]] bool is_sig_blocked(int signo) const {
    return SignalInMask(blocked_, signo);
  }

  [[nodiscard]] bool has_altstack() const {
    return (sigaltstack_.ss_flags & SS_DISABLE) == 0;
  }

  [[nodiscard]] const stack_t &get_altstack() const { return sigaltstack_; }
  [[nodiscard]] k_sigset_t get_blocked_mask() const { return blocked_; }

  [[nodiscard]] k_sigset_t get_blocked_pending() const {
    return get_any_pending() & blocked_;
  }

  void DisableAltStack() { sigaltstack_.ss_flags = SS_DISABLE; }

  Status<void> SigAltStack(const stack_t *ss, stack_t *old_ss) {
    if (old_ss) *old_ss = sigaltstack_;
    if (ss) sigaltstack_ = *ss;
    return {};
  }

  // All updates to blocked_ must happen through this function.
  // Returns false if a signal was pending and the mask was not changed.
  bool ReplaceMask(k_sigset_t new_mask) {
    new_mask &= ~kSignalKernelOnlyMask;
    if (new_mask == blocked_) return true;
    rt::SpinGuard g(sig_q_);
    blocked_ = new_mask;

    // TODO: might need to retarget signals on the shared_q

    SetInterruptFlagIfNeeded();

    return true;
  }

  // ReplaceAndSaveBlocked temporarily adjusts the blocked system call mask
  // during a system call.
  void ReplaceAndSaveBlocked(k_sigset_t mask);

  // RestoreBlockedNeeded returns true if the original blocked system call mask
  // needs to be restored.
  bool RestoreBlockedNeeded() const { return !!saved_blocked_; }

  // RestoreBlocked restores the previous blocked system call mask.
  void RestoreBlocked();

  // Update blocked signal mask
  Status<void> SigProcMask(int how, const unsigned long *nset,
                           unsigned long *oset) {
    if (oset) *oset = blocked_;
    if (!nset) return {};

    k_sigset_t new_sig;

    switch (how) {
      case SIG_BLOCK:
        new_sig = blocked_ | *nset;
        break;
      case SIG_UNBLOCK:
        new_sig = blocked_ & ~*nset;
        break;
      case SIG_SETMASK:
        new_sig = *nset;
        break;
      default:
        return MakeError(EINVAL);
    }

    ReplaceMask(new_sig);
    return {};
  }

  // Add a queued signal. Returns true if a notification is needed.
  bool EnqueueSignal(const siginfo_t &info);

  // Called when a signal has been added on the shared queue to determine if an
  // interrupt should be sent to this thread.
  bool SharedSignalNotifyCheck() {
    rt::SpinGuard g(sig_q_);
    return TestAndSetNotify();
  }

  // Called by this thread when in syscall context to run any pending signals.
  // For convenience, this function takes the return value of the current
  // syscall as its first argument. This function may not return (it may restart
  // a syscall or run a signal handler).
  void DeliverSignals(const Trapframe &entry, int rax);

  // Entry point for a kernel delivered signal.
  [[noreturn]] void DeliverKernelSigToUser(int signo, siginfo_t *info,
                                           const KernelSignalTf &sigframe);

  void Snapshot(ThreadMetadata &s) const &;
  void Restore(ThreadMetadata const &tm);

  // Retrieve the next signal to be delivered to the user.
  std::optional<DeliveredSignal> GetNextSignal(bool *stopped);

  // Pop the next pending signal's information
  std::optional<siginfo_t> PopSigInfo(k_sigset_t blocked, bool reset_flag,
                                      bool *stopped);

 private:
  // Check if signal can be delivered, and returns the action if so.
  // May modifies the sigaction if it is set to SA_ONESHOT
  std::optional<k_sigaction> GetAction(int signo);

  [[nodiscard]] Thread &this_thread() const { return mythread_; }

  // Get the blocked mask to stash in the sigframe (restored up sigreturn).
  // If a syscall saved a previous signal mask, this mask is returned and the
  // saved copy is reset.
  k_sigset_t GetSigframeRestoreMask();

  void ResetInterruptState();

  bool TestAndSetNotify() {
    assert(sig_q_.IsHeld());
    if (notified_) return false;
    notified_ = true;
    return notified_;
  }

  void SetInterruptFlagIfNeeded() {
    assert(sig_q_.IsHeld());
    if (!any_sig_ready()) return;
    notified_ = true;
    set_interrupt_state_interrupted();
  }

  void RestoreBlockedLocked() {
    assert(RestoreBlockedNeeded());
    blocked_ = *saved_blocked_;
    saved_blocked_ = std::nullopt;
    SetInterruptFlagIfNeeded();
  }

  // @sig_q_ lock used to synchronize blocked signals
  SignalQueue sig_q_;
  SignalQueue &shared_q_;
  k_sigset_t blocked_{0};
  std::optional<k_sigset_t> saved_blocked_;
  stack_t sigaltstack_{nullptr, SS_DISABLE, 0};
  Thread &mythread_;
  bool notified_{false};
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

  void Snapshot(ProcessMetadata &s) const &;
  void Restore(ProcessMetadata const &pm);

 private:
  rt::Spin lock_;  // protects @table_
  k_sigaction table_[kNumSignals]{};
};

Status<void> InitSignal();
extern "C" [[noreturn]] void usys_rt_sigreturn(uint64_t rsp);

}  // namespace junction
