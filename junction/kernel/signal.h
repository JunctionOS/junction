// signal.h - support for signal handling

#pragma once

extern "C" {
#include <signal.h>
}

#include <list>

#include "junction/kernel/sigframe.h"

namespace junction {

class Thread;

typedef unsigned long kernel_sigset_t;
typedef void (*sighandler)(int, siginfo_t *info, void *uc);

// The maximum number of signals supported.
inline constexpr int kNumSignals = 64;
inline constexpr size_t kSigSetSizeBytes = 8;
inline constexpr uint32_t kSigStackAutoDisarm = (1U << 31);
inline constexpr int kSigRtMin = 32;
inline constexpr uintptr_t kHandlerDefault = 0x0;
inline constexpr uintptr_t kHandlerIgnore = 0x1;

static_assert(SIG_DFL == nullptr);

inline constexpr uint64_t SigMaskFromSigno(int signo) {
  assert(signo > 0 && signo <= kNumSignals);
  return 1UL << (signo - 1);
}

template <typename... Args>
constexpr uint64_t MultiMask(Args... args) {
  uint64_t mask = 0;
  for (const auto a : {args...}) mask |= SigMaskFromSigno(a);
  return mask;
}

inline constexpr uint64_t kSigDefaultCrash =
    MultiMask(SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGFPE, SIGSEGV, SIGBUS,
              SIGSYS, SIGXCPU, SIGXFSZ);
inline constexpr uint64_t kSigDefaultIgnore =
    MultiMask(SIGCONT, SIGCHLD, SIGWINCH, SIGURG);
inline constexpr uint64_t kSigSynchronous =
    MultiMask(SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE);

inline bool CheckSignalInMask(int signo, unsigned long mask) {
  return (mask & SigMaskFromSigno(signo)) > 0;
}

inline void assert_signal_valid(int sig) {
  assert(sig > 0 && sig <= kNumSignals);
}

// k_sigaction defines the action for a signal (in sync with Linux definition)
struct k_sigaction {
  sighandler handler;
  unsigned long sa_flags;
  void (*restorer)(void);
  kernel_sigset_t sa_mask;

  [[nodiscard]] bool wants_altstack() const {
    return (sa_flags & SA_ONSTACK) > 0;
  }

  [[nodiscard]] bool is_oneshot() const {
    return (sa_flags & SA_RESETHAND) > 0;
  }

  [[nodiscard]] bool is_nodefer() const { return (sa_flags & SA_NODEFER) > 0; }

  [[nodiscard]] bool is_default() const {
    return handler == reinterpret_cast<sighandler>(kHandlerDefault);
  }

  [[nodiscard]] bool is_ignored(int signo) const {
    if (handler == reinterpret_cast<sighandler>(kHandlerIgnore)) return true;
    return is_default() && CheckSignalInMask(signo, kSigDefaultIgnore);
  }

  void reset() {
    handler = reinterpret_cast<sighandler>(kHandlerDefault);
    sa_flags = 0;
  }
};

class ThreadSignalHandler {
 public:
  ThreadSignalHandler() = default;
  ~ThreadSignalHandler() = default;

  void set_sig_pending(int signo) { pending_ |= SigMaskFromSigno(signo); }
  void set_sig_blocked(int signo) { blocked_ |= SigMaskFromSigno(signo); }
  void clear_sig_pending(int signo) { pending_ &= ~SigMaskFromSigno(signo); }
  void clear_sig_blocked(int signo) { blocked_ &= ~SigMaskFromSigno(signo); }

  [[nodiscard]] bool any_sig_pending() const {
    return (access_once(pending_) & ~(access_once(blocked_))) > 0;
  }

  [[nodiscard]] bool is_sig_pending(int signo) const {
    return CheckSignalInMask(signo, pending_);
  }

  [[nodiscard]] bool is_sig_blocked(int signo) const {
    return CheckSignalInMask(signo, access_once(blocked_));
  }

  [[nodiscard]] bool has_altstack() const {
    return (sigaltstack_.ss_flags & SS_DISABLE) == 0;
  }

  [[nodiscard]] const stack_t &get_altstack() const { return sigaltstack_; }
  [[nodiscard]] unsigned long get_blocked_mask() const { return blocked_; }

  [[nodiscard]] unsigned long get_blocked_pending() const {
    return access_once(pending_) & blocked_;
  }

  void DisableAltStack() {
    sigaltstack_.ss_flags = SS_DISABLE;
    thread_self()->tlsvar = 1;
  }

  inline Status<void> SigAltStack(const stack_t *ss, stack_t *old_ss) {
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
  bool EnqueueSignal(int signo, siginfo_t *info);

  // Called by this thread when in syscall context to run any pending signals
  // rax is provided if this is called after a syscall finishes before returning
  // to userspace. This function may not return.
  void RunPending(std::optional<long> rax);

  // Entry point for a kernel delivered signal.
  void DeliverKernelSigToUser(int signo, siginfo_t *info, k_sigframe *sigframe);

 private:
  // Check if signal can be delivered, and returns the action if so.
  // May modifies the sigaction if it is set to SA_ONESHOT
  std::optional<k_sigaction> GetAction(int signo);

  // Pop next queued signal from pending_q_
  siginfo_t PopNextSignal();

  // Update a Linux sigframe with correct altstack, blocked mask, and restorer
  void TransformSigFrame(k_sigframe &sigframe, const k_sigaction &act) const;

  rt::Spin lock_;  // protects @pending_q_, @pending_
  std::list<siginfo_t> pending_q_;
  unsigned long pending_{0};
  unsigned long blocked_{0};
  stack_t sigaltstack_{nullptr, SS_DISABLE, 0};
};

// SignalTable is a table of the signal actions for a process.
class alignas(kCacheLineSize) SignalTable {
 public:
  SignalTable() = default;
  ~SignalTable() = default;

  [[nodiscard]] k_sigaction get_action(int sig) {
    assert_signal_valid(sig);

    rt::SpinGuard g(lock_);
    k_sigaction sa = table_[sig];
    if (sa.is_oneshot()) table_[sig].reset();
    return sa;
  }

  k_sigaction exchange_action(int sig, k_sigaction sa) {
    assert_signal_valid(sig);

    rt::SpinGuard g(lock_);
    return std::exchange(table_[sig], sa);
  }

 private:
  rt::Spin lock_;  // protects @table_
  k_sigaction table_[kNumSignals]{};
};

Status<void> InitSignal();
extern "C" [[noreturn]] void usys_rt_sigreturn(uint64_t rsp);

}  // namespace junction
