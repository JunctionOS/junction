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
inline constexpr uint64_t MultiMask(Args... args) {
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

// Intended to be in sync with kernel definition
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
};

namespace detail {

struct signal_entry {
  k_sigaction saction;
};

struct pending_signal {
  siginfo_t sig;
};

}  // namespace detail

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

  Status<void> SigAltStack(const stack_t *ss, stack_t *old_ss);

  // Update blocked signal mask
  inline Status<void> SigProcMask(int how, const unsigned long *nset,
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
  rt::Spin lock_;  // protects @pending_q_, @pending_
  std::list<detail::pending_signal> pending_q_;
  unsigned long pending_{0};
  unsigned long blocked_{0};
  stack_t sigaltstack_{nullptr, SS_DISABLE, 0};

  // Check if signal can be delivered, and returns the action if so.
  // May modifies the sigaction if it is set to SA_ONESHOT
  std::optional<k_sigaction> GetAction(int signo);

  // Pop next queued signal from pending_q_
  siginfo_t PopNextSignal();

  // Update a Linux sigframe with correct altstack, blocked mask, and restorer
  void TransformSigFrame(k_sigframe &sigframe, const k_sigaction &act) const;
};

class SignalTable {
 public:
  SignalTable() : table_(){};
  ~SignalTable() = default;

  [[nodiscard]] k_sigaction get_action(int sig) {
    assert(sig > 0 && sig <= kNumSignals);

    // Try to read action without acquiring a lock
    unsigned long sgen = signal_tbl_gen_.load(std::memory_order_acquire);
    k_sigaction act = table_[sig].saction;
    unsigned long fgen = signal_tbl_gen_.load();
    if (likely(sgen % 2 == 0 && sgen == fgen)) return act;

    rt::SpinGuard g(lock_);
    return table_[sig].saction;
  }

  std::optional<k_sigaction> atomic_reset_oneshot(int signo) {
    rt::SpinGuard g(lock_);

    k_sigaction sig = table_[signo].saction;
    if (!sig.is_default() && sig.is_oneshot()) {
      table_[signo].saction.handler =
          reinterpret_cast<sighandler>(kHandlerDefault);
      return sig;
    }
    return {};
  }

  void set_action(int sig, const k_sigaction *sa, k_sigaction *osa) {
    assert(sig > 0 && sig <= kNumSignals);
    rt::SpinGuard g(lock_);
    if (osa) *osa = table_[sig].saction;
    if (sa) {
      // Ensure a concurrent reader can detect a partially updated struct
      signal_tbl_gen_.store(signal_tbl_gen_ + 1);
      table_[sig].saction = *sa;
      // If signal is not marked as nodefer, make sure its mask includes sig
      if (!sa->is_nodefer())
        table_[sig].saction.sa_mask |= SigMaskFromSigno(sig);
      signal_tbl_gen_.store(signal_tbl_gen_ + 1);
    }

    // TODO: setting an action SIG_IGN should flush any pending signals
  }

 private:
  rt::Spin lock_;
  std::atomic_size_t signal_tbl_gen_;
  detail::signal_entry table_[kNumSignals];
};

Status<void> InitSignal();
extern "C" [[noreturn]] void usys_rt_sigreturn(uint64_t rsp);

}  // namespace junction
