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

#include "junction/base/arch.h"
#include "junction/base/uid.h"
#include "junction/junction.h"
#include "junction/kernel/file.h"
#include "junction/kernel/itimer.h"
#include "junction/kernel/mm.h"
#include "junction/kernel/signal.h"
#include "junction/kernel/trapframe.h"
#include "junction/limits.h"

namespace junction {

class Process;

inline constexpr unsigned int kNotWaitable = 0;
inline constexpr unsigned int kWaitableExited = WEXITED;
inline constexpr unsigned int kWaitableStopped = WSTOPPED;
inline constexpr unsigned int kWaitableContinued = WCONTINUED;

inline bool SignalIfOwned(struct kthread *k, const thread_t *th) {
  spin_lock_np(&k->lock);
  bool found = access_once(th->cur_kthread) == k->kthread_idx;
  // send IPI with lock held to prevent potential race where the core parks and
  // invalidates its target table entry.
  if (found && uintr_enabled) SendUipi(k->curr_cpu);
  spin_unlock_np(&k->lock);
  if (found && !uintr_enabled) ksys_tgkill(GetLinuxPid(), k->tid, SIGURG);
  return found;
}

// Thread is a UNIX thread object.
class Thread {
 public:
  Thread(std::shared_ptr<Process> proc, pid_t tid)
      : proc_(std::move(proc)), tid_(tid) {}
  ~Thread();

  Thread(Thread &&) = delete;
  Thread &operator=(Thread &&) = delete;
  Thread(const Thread &) = delete;
  Thread &operator=(const Thread &) = delete;

  [[nodiscard]] pid_t get_tid() const { return tid_; }
  [[nodiscard]] Process &get_process() const { return *proc_; }
  [[nodiscard]] uint32_t *get_child_tid() const { return child_tid_; }
  [[nodiscard]] bool needs_interrupt() const {
    assert(GetCaladanThread() == thread_self());
    return thread_interrupted(GetCaladanThread());
  }

  [[nodiscard]] ThreadSignalHandler &get_sighand() { return sighand_; }

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
    assert(th->junction_thread == true);
    auto *ts = reinterpret_cast<Thread *>(th->junction_tstate_buf);
    return *reinterpret_cast<Thread *>(ts);
  }

  void ThreadReady() { thread_ready(GetCaladanThread()); }

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

    thread_t *th = GetCaladanThread();

    // Try to wake this thread's interruptible waiter, if it has one.
    if (deliver_interrupt(th)) return;

    // Try to find the kthread hosting this thread.
    // cur_kthread is updated with the scheduler lock held, and is set to NCPU
    // when it is scheduled out.
    unsigned int kthread = access_once(th->cur_kthread);
    if (kthread < NCPU && SignalIfOwned(ks[kthread], th)) return;

    // thread is hopping around, check with each other kthread.
    for (unsigned int i = 0; i < maxks; i++)
      if (SignalIfOwned(ks[i], th)) return;

    // this thread is not observed running on any core. at this point we have
    // synchronized with each other kthread's scheduler lock, ensuring that
    // the signal will be visible when this thread is next scheduled.
  };

  friend class ThreadSignalHandler;

  // Get the current Trapframe generated when entering the Junction kernel.
  Trapframe &GetTrapframe() {
    DebugSafetyCheck();

    // Function call entry assembly code sets entry_regs to point to a trapframe
    // on the stack. All other entry points must clear this pointer when
    // entering the Junction kernel.
    thread_tf *fncall_regs = GetCaladanThread()->entry_regs;
    if (fncall_regs) {
      fcall_tf.ReplaceTf(fncall_regs);
      return fcall_tf;
    }

    assert(cur_trapframe_);
    return *cur_trapframe_;
  }

  // The caller must be certain that they are executing in the context of a
  // system call and not an interrupt.
  SyscallFrame &GetSyscallFrame() {
    DebugSafetyCheck();

    thread_tf *fncall_regs = GetCaladanThread()->entry_regs;
    if (fncall_regs) {
      fcall_tf.ReplaceTf(fncall_regs);
      return fcall_tf;
    }

    return CastTfToKernelSig();
  }

  FunctionCallTf &ReplaceEntryRegs(thread_tf &tf) {
    assert(rsp_on_syscall_stack(reinterpret_cast<uint64_t>(&tf)));
    GetCaladanThread()->entry_regs = &tf;
    fcall_tf.ReplaceTf(&tf);
    return fcall_tf;
  }

  void CopySyscallRegs(thread_tf &dest) const {
    thread_tf *fncall_regs = GetCaladanThread()->entry_regs;
    if (fncall_regs)
      FunctionCallTf(fncall_regs).CopyRegs(dest);
    else
      CastTfToKernelSig().CopyRegs(dest);
  }

  // Set @tf as the current trapframe generated when entering the Junction
  // kernel. This trapframe must not be a FunctionCallTf.
  void SetTrapframe(Trapframe &tf) {
    DebugSafetyCheck();
    assert(rsp_on_syscall_stack(reinterpret_cast<uint64_t>(&tf)) ||
           &tf == &fcall_tf);
    assert(!rsp_on_syscall_stack(tf.GetRsp()));

    GetCaladanThread()->entry_regs = nullptr;
    cur_trapframe_ = &tf;
  }

  [[nodiscard]] bool in_kernel() const {
    return access_once(GetCaladanThread()->in_syscall);
  }

  [[nodiscard]] bool rsp_on_syscall_stack(uint64_t rsp = GetRsp()) const {
    return IsOnStack(rsp, GetSyscallStack(GetCaladanThread()));
  }

  [[nodiscard]] uint64_t get_syscall_stack_rsp() const {
    return GetSyscallStackBottom(GetCaladanThread());
  }

  [[nodiscard]] uint64_t correct_to_syscall_stack(uint64_t rsp) const {
    if (rsp_on_syscall_stack(rsp)) return rsp;
    return get_syscall_stack_rsp();
  }

  inline void mark_enter_kernel() {
    access_once(GetCaladanThread()->in_syscall) = true;
    barrier();
  }

  inline void mark_leave_kernel() {
    barrier();
    access_once(GetCaladanThread()->in_syscall) = false;
  }

 private:
  friend class Process;

  // Safety check for functions that can only be called by the owning thread
  // when in interrupt or syscall context.
  inline void DebugSafetyCheck() const {
    // Newly created thread doesn't require safety check.
    if (GetCaladanThread()->ready_tsc == 0) return;
    // The function should only be called by the owning thread.
    assert(GetCaladanThread() == thread_self());
    // The returned trapframe is only valid during a syscall (or until the code
    // has switched off of the syscall stack).
    assert(in_kernel() || rsp_on_syscall_stack());
  }

  inline KernelSignalTf &CastTfToKernelSig() const {
    if constexpr (is_debug_build())
      return dynamic_cast<KernelSignalTf &>(*cur_trapframe_);
    return reinterpret_cast<KernelSignalTf &>(*cur_trapframe_);
  }

  // Hot items
  std::shared_ptr<Process> proc_;  // the process this thread is associated with
  const pid_t tid_;                // the thread identifier
  ThreadSignalHandler sighand_{*this};

  Trapframe *cur_trapframe_;

  // Cold items - only accessed at thread exit
  uint32_t *child_tid_{nullptr};  // Used for clone3/exit
  int xstate_;                    // exit state

  // Wrapper around entry trapframe pointer.
  FunctionCallTf fcall_tf;
};

// Make sure that Caladan's thread def has enough room for the Thread class
static_assert(sizeof(Thread) <= sizeof((thread_t *)0)->junction_tstate_buf);

// Process is a UNIX process object.
class Process : public std::enable_shared_from_this<Process> {
 public:
  // Constructor for init process
  Process(pid_t pid, std::shared_ptr<MemoryMap> &&mm, pid_t pgid)
      : pid_(pid), pgid_(pgid), mem_map_(std::move(mm)), parent_(nullptr) {
    RegisterProcess(*this);
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
    RegisterProcess(*this);
  }
  // Constructor for restoring from a snapshot
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
  [[nodiscard]] bool is_stopped() const { return stopped_; }

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

  Status<Thread *> CreateThreadMain();
  Status<Thread *> GetThreadMain();
  Status<Thread *> CreateThread();
  Thread &CreateTestThread();

  void FinishExec(std::shared_ptr<MemoryMap> &&new_mm);

  // Called by a thread to notify that it is exiting.
  // Returns true if this was the last thread.
  bool ThreadFinish(Thread *th);

  // Called when the process finishes
  void ProcessFinish();

  // Called when a process exits, will attempt to notify all threads.
  void DoExit(int status);

  void Signal(const siginfo_t &si) {
    if (SignalInMask(kStopStartSignals, si.si_signo)) {
      SignalStopStart(si.si_signo == SIGSTOP);
      return;
    }
    SignalLocked(rt::UniqueLock<rt::Spin>(shared_sig_q_), si);
  }

  void Signal(int signo) {
    siginfo_t si;
    si.si_signo = signo;
    Signal(si);
  }

  Status<void> SignalThread(pid_t tid, const siginfo_t &si) {
    // Force job control signals to be delivered globally
    if (unlikely(SignalInMask(kProcessWideSignals, si.si_signo))) {
      Signal(si);
      return {};
    }

    rt::SpinGuard g(child_thread_lock_);

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
  void NotifyParentWait(unsigned int state, int status = 0);
  Status<pid_t> DoWait(idtype_t idtype, id_t id, int options, siginfo_t *infop,
                       int *wstatus);
  Status<Process *> FindWaitableProcess(idtype_t idtype, id_t id,
                                        unsigned int wait_flags);

  static std::shared_ptr<Process> Find(pid_t pid) {
    rt::SpinGuard g(pid_map_lock_);
    auto it = pid_to_proc_.find(pid);
    if (it == pid_to_proc_.end()) return {};

    // Might be racing with Process destructor, ensure that ref count has not
    // already hit 0.
    return it->second->weak_from_this().lock();
  }

  // Called by threads to wait for SIGCONT. This call must occur inside of a
  // system call, and GetSyscallFrame() must be contain a trapframe that is
  // ready to be restored.
  void ThreadStopWait(Thread &th);

  Status<void> WaitForFullStop() {
    rt::SpinGuard g(child_thread_lock_);
    rt::Wait(child_thread_lock_, stopped_threads_,
             [&]() { return stopped_count_ == thread_map_.size() || exited_; });
    if (exited_) return MakeError(ESRCH);
    return {};
  }

 private:
  friend class cereal::access;

  void SignalAllThreads() {
    assert(child_thread_lock_.IsHeld());
    for (const auto &[pid, th] : thread_map_)
      if (th->get_sighand().SharedSignalNotifyCheck()) th->SendIpi();
  }

  void FindThreadForSignal(int signo) {
    assert(child_thread_lock_.IsHeld());
    // TODO: add logic to find a thread that hasn't blocked this signal (and
    // ideally is waiting). For now, just signal all threads.
    SignalAllThreads();
  }

  void SignalStopStart(bool stop) {
    rt::ScopedLock g(child_thread_lock_);
    stopped_ = stop;
    if (!stop) {
      stopped_threads_.WakeAll();
      NotifyParentWait(kWaitableContinued);
    } else {
      SignalAllThreads();
    }
  }

  // Places a signal into the Process-wide signal queue and sends an IPI to a
  // thread to deliver it. May also notify a parent if this signal changes this
  // process's waitable state. Takes ownership of @lock, releasing it before
  // sending IPIs to threads.
  void SignalLocked(rt::UniqueLock<rt::Spin> &&lock, const siginfo_t &si) {
    assert(!!lock);
    assert(!SignalInMask(kStopStartSignals, si.si_signo));
    bool needs_ipi = shared_sig_q_.Enqueue(si);
    lock.Unlock();

    rt::ScopedLock g(child_thread_lock_);
    if (si.si_signo == SIGKILL)
      SignalAllThreads();
    else if (needs_ipi)
      FindThreadForSignal(si.si_signo);
  }

  // Constructor for deserialization
  // TODO(cereal): implement
  template <class Archive>
  Process(pid_t pid, Archive &ar) : pid_(pid), signal_tbl_(DeferInit) {
    RegisterProcess(*this);
    ar(signal_tbl_, shared_sig_q_, file_tbl_);
  }

  template <class Archive>
  void save(Archive &ar) const {
    // TODO(cereal): implement
    ar(pid_, signal_tbl_, shared_sig_q_, file_tbl_);
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<Process> &construct) {
    pid_t pid;
    ar(pid);
    construct(pid, ar);
    // TODO(cereal): implement
  }

  const pid_t pid_;         // the process identifier
  pid_t pgid_;              // the process group identifier
  int xstate_;              // exit state
  bool exited_{false};      // If true, the process has been killed
  bool doing_exec_{false};  // True during exec's teardown of existing threads
  rt::ThreadWaker exec_waker_;

  // Processes and Threads contain several locks. Sometimes multiple locks need
  // to be acquired, below is the allowed orderings for acquiring pairs of
  // locks.

  // The three locks are:
  // (1) process-wide shared signal queue lock
  // (2) child_thread_lock_ (manages lifetimes of Threads)
  // (3) per-Thread signal handler/queue lock

  // Additionally, each Process (except the first) has a parent Process, and
  // may also have child processes (different than its Threads).

  // A holder of a per-thread sighand lock can acquire the shared sigq lock.
  // A holder of child_thread_lock_ can acquire a thread's sighand/queue lock.
  // A holder of child_thread_lock_ can acquire the parent's shared sigq lock.
  // A dying Process can acquire its parent's shared sigq lock and its
  // childrens' shared sigq locks.

  // TODO(jfried): describe ref-counting/lifecycle management for Processes and
  // Threads.

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
  // Waiters for changes to the waitable states of children of this Process
  rt::WaitQueue child_waiters_;  // protected by @shared_sig_q_
  std::vector<std::shared_ptr<Process>> child_procs_;

  // @child_thread_lock_ protects @thread_map_, must be held while accessing
  // another Thread to prevent it from exiting.
  rt::Spin child_thread_lock_;
  std::map<pid_t, Thread *> thread_map_;

  // State to manage stopping Threads, protected by @child_thread_lock_.
  // @stopped is set to true when a SIGSTOP is received (and cleared when a
  // SIGCONT is received).
  // All threads have stopped running once stopped_count_ is equal to the number
  // of threads in the thread_map_.
  //
  // NOTE: SIGSTOP and SIGCONT are diverted away from the normal signal
  // processing path, so there is no synchronization with the shared signal
  // queue. The code does synchronize with all thread signal handler locks
  // (potentially sending IPIs) to ensure that updates to this state are visible
  // to each Thread.
  rt::WaitQueue stopped_threads_;
  unsigned int stopped_count_{0};
  bool stopped_{false};

  // Protected by parent_'s shared_sig_q_lock_
  std::shared_ptr<Process> parent_;
  unsigned int wait_state_{kNotWaitable};
  int wait_status_;

  // Timers
  ITimer it_real_{*this};

  static rt::Spin pid_map_lock_;
  static std::map<pid_t, Process *> pid_to_proc_;

  static void RegisterProcess(Process &p) {
    rt::SpinGuard g(pid_map_lock_);
    pid_to_proc_[p.get_pid()] = &p;
  }

  static void DeregisterProcess(Process &p) {
    rt::SpinGuard g(pid_map_lock_);
    size_t nr_removed = pid_to_proc_.erase(p.get_pid());
    assert(nr_removed == 1);
  }
};

// Create a new process.
Status<std::shared_ptr<Process>> CreateInitProcess();

// isJunctionThread returns true if the thread is a part of a process.
inline bool IsJunctionThread(thread_t *th = thread_self()) {
  return th->junction_thread;
}

// mythread returns the Thread object for the running thread.
// Behavior is undefined if the running thread is not part of a process.
inline Thread &mythread() { return Thread::fromCaladanThread(thread_self()); }

// myproc returns the Process object for the running thread.
// Behavior is undefined if the running thread is not part of a process.
inline Process &myproc() { return mythread().get_process(); }

// SigMaskGuard masks signal delivery during its lifetime. The previous signal
// mask is restored unless a signal is pending, in which case the old mask is
// restored after the signal is delivered.
//
// WARNING: The calling thread must be a Junction kernel thread.
class SigMaskGuard {
 public:
  [[nodiscard]] explicit SigMaskGuard(std::optional<k_sigset_t> mask) {
    assert(IsJunctionThread());
    if (!mask) return;

    ThreadSignalHandler &handler = mythread().get_sighand();
    handler.ReplaceAndSaveBlocked(*mask);
  }
  [[nodiscard]] explicit SigMaskGuard(k_sigset_t mask) {
    assert(IsJunctionThread());
    ThreadSignalHandler &handler = mythread().get_sighand();
    handler.ReplaceAndSaveBlocked(mask);
  }
  ~SigMaskGuard() {
    ThreadSignalHandler &handler = mythread().get_sighand();
    if (handler.RestoreBlockedNeeded()) handler.RestoreBlocked();
  }

  // disable copy and move.
  SigMaskGuard(const SigMaskGuard &) = delete;
  SigMaskGuard &operator=(const SigMaskGuard &) = delete;
  SigMaskGuard(SigMaskGuard &&) = delete;
  SigMaskGuard &operator=(SigMaskGuard &&) = delete;
};

}  // namespace junction
