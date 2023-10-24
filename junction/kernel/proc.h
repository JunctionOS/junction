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
      : proc_(std::move(proc)), tid_(tid), sighand_(proc_.get()) {}
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
    return sighand_.any_sig_pending();
  }
  [[nodiscard]] bool in_syscall() const { return access_once(in_syscall_); }

  void set_in_syscall(bool val) { access_once(in_syscall_) = val; }

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

  void OnSyscallEnter() {
    set_in_syscall(true);
    if (unlikely(needs_interrupt())) HandleInterrupt(std::nullopt);
  }

  void OnSyscallLeave(long rax) {
    if (unlikely(needs_interrupt())) HandleInterrupt(rax);

    // TODO(jf): can we put this into HandleInterrupt?
    get_sighand().RestoreBlocked();
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
    if (sighand_.EnqueueSignal(&info)) SendIpi();
  }

  // TODO!
  void SendIpi() {
    /*
     * Signals can be delivered at the following points:
     * (1) When returning from syscalls: delivery is arranged for any pending
     * signals.
     * (2) When Caladan's jmp_thread* runs a thread: this will check if
     * both a signal is pending and the resuming thread is not in a syscall,
     * then it will arrange for a signal handler to run.
     * (3) Upon IPI delivery, if a thread is running and not in a syscall.
     */

    /*
     * Sequence of events to ensure that a signal is delivered:
     * (1) A signal is enqueued using in a thread's sighand_.EnqueueSignal().
     * (2) try_wake_blocked_thread() checks if a lock is registered protecting
     * an interruptible wait. If so, it synchronizes with the waiter using that
     * lock, waking the waiter if necessary. Interruptible waiters check for
     * signals before sleeping (while holding this lock).
     * (3) Check if either the thread is in a in_syscall or the stack is not
     * busy.
     * (4) If neither is true, send an IPI to the core hosting the thread.
     */
    try_wake_blocked_thread(GetCaladanThread());
  };

  // Called by a thread to run pending interrupts. This function may not return.
  void HandleInterrupt(std::optional<long> rax) {
    assert(thread_self() == GetCaladanThread());
    sighand_.RunPending(rax);
  }

  void SetSyscallFrame(void *frame) { cur_syscall_frame_ = frame; }
  [[nodiscard]] void *GetSyscallFrame() const { return cur_syscall_frame_; }

  friend class ThreadSignalHandler;

  rt::Spin &get_waker_lock() { return waker_lock_; }

 private:
  std::shared_ptr<Process> proc_;  // the process this thread is associated with
  uint32_t *child_tid_{nullptr};   // Used for clone3/exit
  const pid_t tid_;                // the thread identifier
  bool in_syscall_;
  int xstate_;  // exit state
  rt::Spin waker_lock_;
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
      : pid_(pid), pgid_(pgid), mem_map_(std::move(mm)), parent_(nullptr) {
    all_procs.Add(1);
  }
  // Constructor for all other processes
  Process(pid_t pid, std::shared_ptr<MemoryMap> mm, FileTable &ftbl,
          rt::ThreadWaker &&w, std::shared_ptr<Process> parent, pid_t pgid)
      : pid_(pid),
        pgid_(pgid),
        vfork_waker_(std::move(w)),
        file_tbl_(ftbl),
        mem_map_(std::move(mm)),
        parent_(std::move(parent)) {
    all_procs.Add(1);
  }

  ~Process();

  Process(Process &&) = delete;
  Process &operator=(Process &&) = delete;
  Process(const Process &) = delete;
  Process &operator=(const Process &) = delete;

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

  static void WaitAll() { all_procs.Wait(); }

  Status<void> SignalLocked(siginfo_t &si) {
    assert(shared_sig_q_.IsHeld());
    shared_sig_q_.Enqueue(&si);
    if (si.si_signo == SIGCLD) child_waiters_.WakeAll();

    // TODO(jf): find thread to send an IPI to
    for (const auto &[pid, th] : thread_map_) {
      // FIXME signalling a blocked thread might try to acquire this lock,
      // so drop for now.
      shared_sig_q_.Unlock();
      th->SendIpi();
      shared_sig_q_.Lock();
      break;
    }

    return {};
  }

  Status<void> Signal(siginfo_t &si) {
    {
      rt::SpinGuard g(shared_sig_q_);
      shared_sig_q_.Enqueue(&si);
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

  Status<void> SignalThread(pid_t tid, siginfo_t *si) {
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
    return SignalThread(tid, &si);
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

  static rt::WaitGroup all_procs;
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
