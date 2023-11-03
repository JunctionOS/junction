// proc.h - the process abstraction

#pragma once

extern "C" {
#include <runtime/interruptible_wait.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ucontext.h>
}

#include <map>
#include <memory>

#include "junction/base/uid.h"
#include "junction/junction.h"
#include "junction/kernel/file.h"
#include "junction/kernel/itimer.h"
#include "junction/kernel/mm.h"
#include "junction/kernel/signal.h"
#include "junction/limits.h"

namespace junction {

class Process;

enum class ThreadState : uint64_t {
  kInvalid = 0,
  kActive = 1,
};

inline constexpr unsigned int kNotWaitable = 0;
inline constexpr unsigned int kWaitableExited = WEXITED;
inline constexpr unsigned int kWaitableStopped = WSTOPPED;
inline constexpr unsigned int kWaitableContinued = WCONTINUED;

// Thread is a UNIX thread object.
class Thread {
 public:
  Thread(std::shared_ptr<Process> proc, pid_t tid)
      : proc_(std::move(proc)), tid_(tid), sighand_(*this) {}
  ~Thread();

  Thread(Thread &&) = delete;
  Thread &operator=(Thread &&) = delete;
  Thread(const Thread &) = delete;
  Thread &operator=(const Thread &) = delete;

  static void operator delete(void *ptr) noexcept {
    // delete should only be called by a unique pointer handling a thread object
    // before it first runs. this goal here is to be able to use unique pointers
    // for cleanup in functions that create new threads.
    BUG_ON(ptr == thread_self()->junction_tstate_buf);
    auto *bufptr =
        reinterpret_cast<decltype(thread_t::junction_tstate_buf) *>(ptr);
    thread_free(container_of(bufptr, thread_t, junction_tstate_buf));
  }

  [[nodiscard]] pid_t get_tid() const { return tid_; }
  [[nodiscard]] Process &get_process() const { return *proc_; }
  [[nodiscard]] uint32_t *get_child_tid() const { return child_tid_; }
  [[nodiscard]] bool needs_interrupt() const {
    assert(GetCaladanThread() == thread_self());
    return thread_interrupted(GetCaladanThread());
  }
  [[nodiscard]] bool in_syscall() const { return access_once(in_syscall_); }

  void set_in_syscall(bool val) {
    barrier();
    access_once(in_syscall_) = val;
    barrier();
  }

  [[nodiscard]] ThreadSignalHandler &get_sighand() { return sighand_; }
  [[nodiscard]] bool has_altstack() const { return sighand_.has_altstack(); }

  void set_child_tid(uint32_t *tid) { child_tid_ = tid; }
  void set_xstate(int xstate) { xstate_ = xstate; }

  thread_t *GetCaladanThread() {
    auto *ptr =
        reinterpret_cast<decltype(thread_t::junction_tstate_buf) *>(this);
    return container_of(ptr, thread_t, junction_tstate_buf);
  }

  const thread_t *GetCaladanThread() const {
    const auto *ptr =
        reinterpret_cast<decltype(thread_t::junction_tstate_buf) *>(
            const_cast<Thread *>(this));
    return container_of(ptr, thread_t, junction_tstate_buf);
  }

  static Thread &fromCaladanThread(thread_t *th) {
    assert(static_cast<ThreadState>(th->tlsvar) == ThreadState::kActive);
    auto *ts = reinterpret_cast<Thread *>(th->junction_tstate_buf);
    return *reinterpret_cast<Thread *>(ts);
  }

  void ThreadReady() { thread_ready(GetCaladanThread()); }

  void OnSyscallEnter() { set_in_syscall(true); }

  void OnSyscallLeave(long rax) {
    if (unlikely(needs_interrupt())) HandleInterrupt(rax);

    void *frame = GetSyscallFrame();

    while (true) {
      SetSyscallFrame(nullptr);
      set_in_syscall(false);

      // A signal may have been queued but not delivered between the last check
      // of needs_interrupt() and clearing the in_syscall flag. Check once
      // more for pending interrupts.
      if (likely(!needs_interrupt())) break;
      set_in_syscall(true);
      SetSyscallFrame(frame);
      HandleInterrupt(rax);
    }
  }

  void Kill() {
    siginfo_t info;
    info.si_signo = SIGKILL;
    if (sighand_.EnqueueSignal(info)) SendIpi();
  }

  void SendIpi() {
    /*
     * Signals can be delivered at the following points:
     * (1) When returning from syscalls: delivery is arranged for any pending
     * signals.
     * (2) When Caladan's jmp_thread* runs a thread: this will check if
     * the resuming thread is not in a syscall; if so it will acquire the signal
     * handler lock and check for pending signals.
     * (3) Upon IPI delivery, if a thread is running and not in a syscall.
     */

    /*
     * Sequence of events to ensure that a signal is delivered:
     * (1) A signal is enqueued using in a thread's sighand_.EnqueueSignal().
     * (2) deliver_interrupt() tries to wake the thread if it is blocked.
     * (3) if deliver_interrupt doesn't result in a thread_ready(), we look for
     * the kthread running this thread to send an interrupt: we do a racy read
     * of the thread's kthread, and synchronize with the kthread's scheduler
     * lock to confirm the thread is actively using this kthread. send an
     * interrupt to this kthread if so.
     * (4) if the thread rescheduled while we were acquiring the lock, or was
     * already parked/waking, synchronize with each other kthread's scheduler
     * lock and check if this kthread is active there. if so, send an interrupt.
     * (5) we may not locate the core running this thread (perhaps none are). by
     * synchronizing with each other scheduler lock, we ensure that the enqueued
     * signal will be visible when the thread resumes.
     */

    // Try to wake this thread's interruptible waiter, if it has one.
    if (deliver_interrupt(GetCaladanThread())) return;

    // Try to find the kthread hosting this thread.
    // cur_kthread is updated with the scheduler lock held, and is set to NCPU
    // when it is scheduled out.
    unsigned int kthread = access_once(GetCaladanThread()->cur_kthread);
    if (kthread < NCPU) {
      spin_lock_np(&ks[kthread]->lock);
      bool found = access_once(GetCaladanThread()->cur_kthread) == kthread;
      spin_unlock_np(&ks[kthread]->lock);
      if (found) {
        ksys_tgkill(GetLinuxPid(), ks[kthread]->tid, SIGURG);
        return;
      }
    }

    // kthread is hopping around, check with each other kthread.
    for (unsigned int i = 0; i < maxks; i++) {
      spin_lock_np(&ks[i]->lock);
      bool found = access_once(GetCaladanThread()->cur_kthread) == i;
      spin_unlock_np(&ks[i]->lock);
      if (found) {
        ksys_tgkill(GetLinuxPid(), ks[i]->tid, SIGURG);
        return;
      }
    }

    // this thread is not observed running on any core. at this point we have
    // synchronized with each other kthread's scheduler lock, ensuring that
    // the signal will be visible when this thread is next scheduled.
  };

  // Called by a thread to run pending interrupts. This function may not return.
  void HandleInterrupt(std::optional<long> rax) {
    assert(thread_self() == GetCaladanThread());
    sighand_.RunPending(rax);
  }

  void SetSyscallFrame(void *frame) { cur_syscall_frame_ = frame; }
  [[nodiscard]] void *GetSyscallFrame() const { return cur_syscall_frame_; }

  friend class ThreadSignalHandler;

 private:
  std::shared_ptr<Process> proc_;  // the process this thread is associated with
  uint32_t *child_tid_{nullptr};   // Used for clone3/exit
  const pid_t tid_;                // the thread identifier
  bool in_syscall_;
  int xstate_;  // exit state
  ThreadSignalHandler sighand_;
  void *cur_syscall_frame_;
};

// Make sure that Caladan's thread def has enough room for the Thread class
static_assert(sizeof(Thread) <= sizeof((thread_t *)0)->junction_tstate_buf);

// Process is a UNIX process object.
class Process : public std::enable_shared_from_this<Process> {
 public:
  // Constructor for init process
  Process(pid_t pid, std::shared_ptr<MemoryMap> &&mm, pid_t pgid)
      : pid_(pid), pgid_(pgid), mem_map_(std::move(mm)), parent_(nullptr) {}
  // Constructor for all other processes
  Process(pid_t pid, std::shared_ptr<MemoryMap> mm, FileTable &ftbl,
          rt::ThreadWaker &&w, std::shared_ptr<Process> parent, pid_t pgid)
      : pid_(pid),
        pgid_(pgid),
        vfork_waker_(std::move(w)),
        file_tbl_(ftbl),
        mem_map_(std::move(mm)),
        parent_(std::move(parent)) {}

  ~Process();

  Process(Process &&) = delete;
  Process &operator=(Process &&) = delete;
  Process(const Process &) = delete;
  Process &operator=(const Process &) = delete;

  // Gets a shared pointer to this process.
  [[nodiscard]] std::shared_ptr<Process> get_this() {
    return shared_from_this();
  };

  [[nodiscard]] pid_t get_pid() const { return pid_; }
  [[nodiscard]] pid_t get_pgid() const { return pgid_; }
  [[nodiscard]] FileTable &get_file_table() { return file_tbl_; }
  [[nodiscard]] MemoryMap &get_mem_map() { return *mem_map_; }
  [[nodiscard]] SignalTable &get_signal_table() { return signal_tbl_; }
  [[nodiscard]] SignalQueue &get_signal_queue() { return shared_sig_q_; }
  [[nodiscard]] rlimit get_limit_nofile() const { return limit_nofile_; }
  [[nodiscard]] bool exited() const { return access_once(exited_); }
  [[nodiscard]] ITimer &get_itimer() { return it_real_; }

  [[nodiscard]] const std::string_view get_bin_path() const {
    return binary_path_;
  }

  void set_bin_path(const std::string_view &path) {
    binary_path_ = std::string(path);
  }

  void set_limit_nofile(const rlimit *rlim) {
    limit_nofile_.rlim_cur = rlim->rlim_cur;
    limit_nofile_.rlim_max = rlim->rlim_max;
  }

  // Create a vforked process from this one.
  Status<std::shared_ptr<Process>> CreateProcessVfork(rt::ThreadWaker &&w);

  Status<std::unique_ptr<Thread>> CreateThreadMain();
  Status<std::unique_ptr<Thread>> CreateThread();
  Thread &CreateTestThread();
  void FinishExec(std::shared_ptr<MemoryMap> &&new_mm);

  // Called by a thread to notify that it is exiting.
  // Returns true if this was the last thread.
  bool ThreadFinish(Thread *th);

  // Called when the process finishes
  void ProcessFinish();

  // Called when a process exits, will attempt to notify all threads.
  void DoExit(int status);

  Status<void> SignalLocked(const siginfo_t &si) {
    assert(shared_sig_q_.IsHeld());
    shared_sig_q_.Enqueue(si);
    if (si.si_signo == SIGCLD) child_waiters_.WakeAll();

    // TODO(jf): find thread to send an IPI to
    for (const auto &[pid, th] : thread_map_) {
      th->SendIpi();
      break;
    }

    return {};
  }

  Status<void> Signal(const siginfo_t &si) {
    {
      rt::SpinGuard g(shared_sig_q_);
      shared_sig_q_.Enqueue(si);
      if (si.si_signo == SIGCLD) child_waiters_.WakeAll();
    }

    // TODO(jf): find thread to send an IPI to
    return {};
  }

  Status<void> Signal(int signo) {
    siginfo_t si;
    si.si_signo = signo;
    return Signal(si);
  }

  Status<void> SignalThread(pid_t tid, const siginfo_t &si) {
    rt::SpinGuard g(shared_sig_q_);

    auto it = thread_map_.find(tid);
    if (it == thread_map_.end()) return MakeError(ESRCH);

    Thread &th = *it->second;
    if (th.get_sighand().EnqueueSignal(si)) th.SendIpi();
    return {};
  }

  Status<void> SignalThread(pid_t tid, int signo) {
    siginfo_t si;
    si.si_signo = signo;
    return SignalThread(tid, si);
  }

  [[nodiscard]] unsigned int get_wait_state() const { return wait_state_; }

  void FillWaitInfo(siginfo_t &info) const;
  int GetWaitStatus() const;
  void ReapChild(Process *child);
  void NotifyParentWait(unsigned int state, int status);
  Status<pid_t> DoWait(idtype_t idtype, id_t id, int options, siginfo_t *infop,
                       int *wstatus);
  Status<Process *> FindWaitableProcess(idtype_t idtype, id_t id,
                                        unsigned int wait_flags);

 private:
  const pid_t pid_;     // the process identifier
  pid_t pgid_;          // the process group identifier
  int xstate_;          // exit state
  bool exited_{false};  // If true, the process has been killed

  // TODO: enforce limit
  rlimit limit_nofile_{kDefaultNoFile,
                       kDefaultNoFile};  // current rlimit for RLIMIT_NOFILE
  std::string binary_path_;

  // Wake this blocked thread that is waiting for the vfork thread to exec().
  rt::ThreadWaker vfork_waker_;

  //
  // Per-process kernel subsystems
  //

  // File descriptor table
  FileTable file_tbl_;
  // Memory mappings
  std::shared_ptr<MemoryMap> mem_map_;

  // Signal table
  SignalTable signal_tbl_;

  // Protected by shared_sig_q_lock_
  SignalQueue shared_sig_q_;
  rt::WaitQueue child_waiters_;
  std::vector<std::shared_ptr<Process>> child_procs_;
  std::map<pid_t, Thread *> thread_map_;

  // Protected by parent_'s shared_sig_q_lock_
  std::shared_ptr<Process> parent_;
  unsigned int wait_state_{kNotWaitable};
  int wait_status_;

  // Timers
  ITimer it_real_{this};
};

// Create a new process.
Status<std::shared_ptr<Process>> CreateInitProcess();

// isJunctionThread returns true if the thread is a part of a process.
inline bool IsJunctionThread(thread_t *th = thread_self()) {
  return static_cast<ThreadState>(th->tlsvar) == ThreadState::kActive;
}

// mythread returns the Thread object for the running thread.
// Behavior is undefined if the running thread is not part of a process.
inline Thread &mythread() { return Thread::fromCaladanThread(thread_self()); }

// myproc returns the Process object for the running thread.
// Behavior is undefined if the running thread is not part of a process.
inline Process &myproc() { return mythread().get_process(); }

}  // namespace junction
