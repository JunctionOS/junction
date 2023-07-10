// signal.h - support for signal handling

#pragma once

extern "C" {
#include <signal.h>
}

#include <deque>

namespace junction {

class Thread;

typedef unsigned long kernel_sigset_t;
typedef void (*sighandler)(int, siginfo_t *info, void *uc);

// The maximum number of signals supported.
inline constexpr int kNumSignals = 64;
inline constexpr size_t kSigSetSizeBytes = 8;
inline constexpr uint32_t kSigStackAutoDisarm = (1U << 31);
inline constexpr int kSigRtMin = 32;

// TODO: use bitmap
#define SIGMASK(sig) (1UL << ((sig)-1))
#define SIGINMASK(sig, mask)                                       \
  ((sig) > 0 && (unsigned long)(sig) < (unsigned long)kSigRtMin && \
   (SIGMASK(sig) & (mask)))

inline constexpr uint64_t kSigDefaultCrash =
    (SIGMASK(SIGQUIT) | SIGMASK(SIGILL) | SIGMASK(SIGTRAP) | SIGMASK(SIGABRT) |
     SIGMASK(SIGFPE) | SIGMASK(SIGSEGV) | SIGMASK(SIGBUS) | SIGMASK(SIGSYS) |
     SIGMASK(SIGXCPU) | SIGMASK(SIGXFSZ));

inline constexpr uint64_t kSigDefaultIgnore =
    (SIGMASK(SIGCONT) | SIGMASK(SIGCHLD) | SIGMASK(SIGWINCH) | SIGMASK(SIGURG));

inline constexpr uint64_t kSigSynchronous =
    (SIGMASK(SIGSEGV) | SIGMASK(SIGBUS) | SIGMASK(SIGILL) | SIGMASK(SIGTRAP) |
     SIGMASK(SIGFPE));

struct k_sigaction {
  sighandler handler;
  unsigned long sa_flags;
  void (*restorer)(void);
  kernel_sigset_t sa_mask;

  [[nodiscard]] bool wants_altstack() const {
    return (sa_flags & SA_ONSTACK) > 0;
  }

  [[nodiscard]] bool is_nodefer() const { return (sa_flags & SA_NODEFER) > 0; }

  [[nodiscard]] bool is_ignored() const {
    return handler == reinterpret_cast<sighandler>(SIG_IGN);
  }

  [[nodiscard]] bool is_default() const {
    return handler == reinterpret_cast<sighandler>(SIG_DFL);
  }
};

namespace detail {

struct signal_entry {
  struct k_sigaction saction;
};

struct pending_signal {
  siginfo_t sig;
};

}  // namespace detail

class ThreadSignalHandler {
 public:
  ThreadSignalHandler() = default;
  ~ThreadSignalHandler() = default;

  void set_sig_pending(int signo) { pending_ |= SIGMASK(signo); }
  void set_sig_blocked(int signo) { blocked_ |= SIGMASK(signo); }
  void clear_sig_pending(int signo) { pending_ &= ~SIGMASK(signo); }
  void clear_sig_blocked(int signo) { blocked_ &= ~SIGMASK(signo); }

  [[nodiscard]] bool any_sig_pending() const {
    return (pending_ & ~blocked_) > 0;
  }

  [[nodiscard]] bool is_sig_pending(int signo) const {
    return SIGINMASK(signo, pending_);
  }

  [[nodiscard]] bool is_sig_blocked(int signo) const {
    return SIGINMASK(signo, blocked_);
  }

  [[nodiscard]] bool has_altstack() const {
    return (sigaltstack_.ss_flags & SS_DISABLE) == 0;
  }

  [[nodiscard]] const stack_t &get_altstack() const { return sigaltstack_; }
  [[nodiscard]] unsigned long get_blocked_mask() const { return blocked_; }

  void DisableAltStack() { sigaltstack_.ss_flags = SS_DISABLE; }

  void SigAltStack(const stack_t *ss, stack_t *old_ss) {
    if (old_ss) *old_ss = sigaltstack_;
    if (ss) sigaltstack_ = *ss;
  }

  Status<void> SigProcMask(int how, const unsigned long *nset,
                           unsigned long *oset) {
    if (oset) *oset = blocked_;
    if (!nset) return {};

    switch (how) {
      case SIG_BLOCK:
        blocked_ |= *nset;
        break;
      case SIG_UNBLOCK:
        blocked_ ^= *nset;
        break;
      case SIG_SETMASK:
        blocked_ = *nset;
        break;
      default:
        return MakeError(EINVAL);
    }
    return {};
  }

  [[nodiscard]] bool check_signal_ignored(int signo,
                                          struct k_sigaction &sa) const {
    // is it a legacy signal that is already enqueued?
    if (signo < kSigRtMin && is_sig_pending(signo)) return true;

    // is the handler set to SIG_IGN?
    if (sa.is_ignored()) return true;

    // if handler is SIG_DFL, is the default action to ignore?
    return sa.is_default() && SIGINMASK(signo, kSigDefaultIgnore);
  }

  [[nodiscard]] bool check_signal_crash(int signo,
                                        struct k_sigaction &sa) const {
    return sa.is_default() && SIGINMASK(signo, kSigDefaultCrash);
  }

  void EnqueueSignal(int signo, siginfo_t *info);

  void UpdateBlocked(unsigned long blocked) { blocked_ = blocked; }

 private:
  std::deque<detail::pending_signal> pending_q_;
  unsigned long pending_{0};
  unsigned long blocked_{0};
  stack_t sigaltstack_{nullptr, SS_DISABLE, 0};
};

class SignalTable {
 public:
  SignalTable() : table_(){};
  ~SignalTable() = default;

  [[nodiscard]] struct k_sigaction get_action(int sig) {
    assert(sig > 0 && sig < kNumSignals);

    // Try to read action without acquiring a lock
    unsigned long sgen = signal_tbl_gen_.load(std::memory_order_acquire);
    struct k_sigaction act = table_[sig].saction;
    unsigned long fgen = signal_tbl_gen_.load();
    if (likely(sgen % 2 == 0 && sgen == fgen)) return act;

    rt::SpinGuard g(lock_);
    return table_[sig].saction;
  }

  void set_action(int sig, const struct k_sigaction *sa,
                  struct k_sigaction *osa) {
    assert(sig > 0 && sig < kNumSignals);
    rt::SpinGuard g(lock_);
    if (osa) *osa = table_[sig].saction;
    if (sa) {
      // Ensure a concurrent reader can detect a partially updated struct
      signal_tbl_gen_.store(signal_tbl_gen_ + 1);
      table_[sig].saction = *sa;
      signal_tbl_gen_.store(signal_tbl_gen_ + 1);
    }
  }

 private:
  rt::Spin lock_;
  std::atomic_size_t signal_tbl_gen_;
  detail::signal_entry table_[kNumSignals];
};

Status<void> InitSignal();

}  // namespace junction
