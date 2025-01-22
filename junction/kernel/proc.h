// proc.h - the process abstraction

#pragma once

extern "C" {
#include <runtime/interruptible_wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
}

#include <cstring>
#include <map>
#include <memory>

#include "junction/base/arch.h"
#include "junction/base/uid.h"
#include "junction/control/serverless.h"
#include "junction/fs/file.h"
#include "junction/fs/fs.h"
#include "junction/fs/procfs/procfs.h"
#include "junction/junction.h"
#include "junction/kernel/itimer.h"
#include "junction/kernel/mm.h"
#include "junction/kernel/signal.h"
#include "junction/kernel/trapframe.h"
#include "junction/kernel/usys.h"
#include "junction/limits.h"
#include "junction/snapshot/cereal.h"

namespace junction {

class Process;

void AcquirePid(pid_t pid, std::optional<pid_t> pgid = std::nullopt,
                std::optional<pid_t> sid = std::nullopt);
void SetInitProc(std::shared_ptr<Process> proc);

inline constexpr unsigned int kNotWaitable = 0;
inline constexpr unsigned int kWaitableExited = WEXITED;
inline constexpr unsigned int kWaitableStopped = WSTOPPED;
inline constexpr unsigned int kWaitableContinued = WCONTINUED;
inline constexpr uint64_t kCapabilityFull =
    std::numeric_limits<uint64_t>::max();
inline constexpr long kMaxCapability = 63;

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

struct Credential {
  Credential() : ruid(0), euid(0), suid(0), rgid(0), egid(0), sgid(0) {}
  Credential(uid_t uid, gid_t gid)
      : ruid(uid), euid(uid), suid(uid), rgid(gid), egid(gid), sgid(gid) {}
  uid_t ruid;
  uid_t euid;
  uid_t suid;
  gid_t rgid;
  gid_t egid;
  gid_t sgid;
  std::vector<gid_t> supplementary_groups;

  // Capability sets
  uint64_t bounding{kCapabilityFull};
  uint64_t ambient{kCapabilityFull};
  uint64_t permitted{kCapabilityFull};
  uint64_t effective{kCapabilityFull};
  uint64_t inheritable{0};

  [[nodiscard]] inline bool in_set(uint64_t set, long cap) const {
    return set & (1UL << cap);
  }

  Status<void> UpdateCapabilities(uint64_t new_permitted,
                                  uint64_t new_effective,
                                  uint64_t new_inheritable) {
    if (!in_set(effective, CAP_SETPCAP)) {
      // Inheritable must be a subset of inheritable + permitted.
      if (new_inheritable & ~(inheritable | permitted)) return MakeError(EPERM);
    }

    // Can't exceed the bounding set.
    if (new_inheritable & ~(inheritable | bounding)) return MakeError(EPERM);

    // Can't add things not previously in permitted set.
    if (new_permitted & ~permitted) return MakeError(EPERM);

    // Effective should be a subset of permitted.
    if (new_effective & ~new_permitted) return MakeError(EPERM);

    permitted = new_permitted;
    effective = new_effective;
    inheritable = new_inheritable;
    ambient = ambient & (permitted & inheritable);
    return {};
  }

  [[nodiscard]] bool in_bounding_set(long cap) const {
    return cap <= kMaxCapability && in_set(bounding, cap);
  }

  void DropCap(uint64_t &set, long cap) { set &= ~(1ULL << cap); }

  Status<void> DropBoundedCap(long cap) {
    if (!in_set(effective, CAP_SETPCAP)) return MakeError(EPERM);
    if (cap > kMaxCapability) return MakeError(EINVAL);
    DropCap(bounding, cap);
    DropCap(ambient, cap);
    DropCap(permitted, cap);
    DropCap(effective, cap);
    DropCap(inheritable, cap);
    return {};
  }

  Status<void> AmbientRaise(long cap) {
    if (cap > kMaxCapability) return MakeError(EINVAL);
    if (!in_set(inheritable & permitted, cap)) return MakeError(EPERM);
    ambient |= (1ULL << cap);
    return {};
  }

  Status<void> AmbientLower(long cap) {
    if (cap > kMaxCapability) return MakeError(EINVAL);
    ambient &= ~(1ULL << cap);
    return {};
  }

  [[nodiscard]] bool in_ambient_set(long cap) {
    return cap <= kMaxCapability && in_set(ambient, cap);
  }

  void AmbientClear() { ambient = 0; }

  void OnExec() {
    // TODO!
  }

  template <class Archive>
  void serialize(Archive &ar) {
    ar(ruid, euid, suid, rgid, egid, sgid, supplementary_groups);
    ar(bounding, ambient, permitted, effective, inheritable);
  }
};

class ThreadRef;

// Thread is a UNIX thread object.
class Thread {
 public:
  Thread(std::shared_ptr<Process> proc, pid_t tid, const Credential &cred)
      : proc_(std::move(proc)), tid_(tid) {
    InitCold(cred);
  }
  ~Thread();

  Thread(Thread &&) = delete;
  Thread &operator=(Thread &&) = delete;
  Thread(const Thread &) = delete;
  Thread &operator=(const Thread &) = delete;

  [[nodiscard]] pid_t get_tid() const { return tid_; }
  [[nodiscard]] Process &get_process() const { return *proc_; }
  [[nodiscard]] uint32_t *get_child_tid() const { return cold().child_tid_; }
  [[nodiscard]] bool needs_interrupt() const {
    assert(GetCaladanThread() == thread_self());
    return thread_interrupted(GetCaladanThread());
  }

  [[nodiscard]] ThreadSignalHandler &get_sighand() { return cold().sighand_; }
  [[nodiscard]] procfs::ProcFSData &get_procfs() { return cold().procfs_data_; }
  [[nodiscard]] Credential &get_creds() { return cold().creds_; }

  void set_child_tid(uint32_t *tid) { cold().child_tid_ = tid; }
  void set_xstate(int xstate) { cold().xstate_ = xstate; }

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

  void ThreadReady(bool head = false) {
    if (!head)
      thread_ready(GetCaladanThread());
    else
      thread_ready_head(GetCaladanThread());
  }

  void Kill() {
    siginfo_t info;
    info.si_signo = SIGKILL;
    if (get_sighand().EnqueueSignal(info)) SendIpi();
  }

  [[nodiscard]] Duration GetRuntime() {
    return Duration(thread_get_total_cycles(GetCaladanThread()) /
                    cycles_per_us);
  }

  // Note some documentation update needed below. It is now the case that when a
  // uthread is run by the caladan scheduler exactly one of the following is
  // true: (A) it is in a blocked syscall or (B) it was preempted. The signal
  // handlers for preemption guarantee the that resumed trapframe will do a
  // signal check before jumping into user code, so the explicit check at jmp
  // thread is no longer needed.
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

  // Zeros memory (using madvise) above the current RSP for a stopped thread, if
  // it is safe to do so.
  Status<void> DropUnusedStack();

  template <class Archive>
  void DoSave(Archive &ar) {
    uintptr_t child_tid_ptr = reinterpret_cast<uintptr_t>(cold().child_tid_);
    ar(child_tid_ptr, cold().xstate_, get_sighand());
    GetTrapframe().DoSave(ar, cold().stopped_rax_);

    Status<void> ret = DropUnusedStack();
    if (unlikely(!ret)) {
      LOG(ERR) << "Failed to trim stack: " << ret.error();
      syscall_exit(-1);
    }

    bool has_fsbase = GetCaladanThread()->has_fsbase;
    ar(has_fsbase);
    if (has_fsbase) ar(GetCaladanThread()->tf.fsbase);
    ar(get_creds());
  }

  Thread(std::shared_ptr<Process> &&proc, pid_t tid,
         cereal::BinaryInputArchive &ar)
      : proc_(proc), tid_(tid) {
    InitCold();
    uintptr_t child_tid_ptr;
    ar(child_tid_ptr, cold().xstate_, get_sighand());
    cold().child_tid_ = reinterpret_cast<uint32_t *>(child_tid_ptr);

    mark_enter_kernel();

    LoadTrapframe(ar, this);
    bool has_fsbase = false;
    ar(has_fsbase);
    GetCaladanThread()->has_fsbase = has_fsbase;
    if (GetCaladanThread()->has_fsbase) ar(GetCaladanThread()->tf.fsbase);
    ar(get_creds());
  }

  // Take a reference to this Thread.
  ThreadRef get_ref();

  void OnExec() {
    get_sighand().OnExec();
    set_child_tid(nullptr);
    get_creds().OnExec();
  }

 private:
  friend class Process;
  friend class ThreadRef;
  friend void FinishExit(int status) __noreturn;

  // Cold per-thread data that is stored outside of the Thread class.
  struct ThreadColdData {
    ThreadColdData(Thread &th) : sighand_(th) {}
    ThreadColdData(Thread &th, const Credential &cred)
        : sighand_(th), creds_(cred) {}
    int xstate_;  // exit state
    int stopped_rax_;
    ThreadSignalHandler sighand_;
    Credential creds_;
    std::atomic<size_t> ref_count_{1};
    // Data for procfs entries for this thread.
    procfs::ProcFSData procfs_data_;
    uint32_t *child_tid_{nullptr};  // Used for clone3/exit
  };

  ThreadColdData &cold() {
    return *reinterpret_cast<ThreadColdData *>(
        GetCaladanThread()->junction_cold_state_buf);
  }

  const ThreadColdData &cold() const {
    return *reinterpret_cast<const ThreadColdData *>(
        GetCaladanThread()->junction_cold_state_buf);
  }

  void InitCold(const Credential &creds) {
    new (&cold()) ThreadColdData(*this, creds);
  }
  void InitCold() { new (&cold()) ThreadColdData(*this); }

  void DestroyCold() { (&cold())->~ThreadColdData(); }

  // Make sure that Caladan's thread def has enough room for the Thread class
  static_assert(offsetof(thread_t, junction_cold_state_buf) %
                    alignof(ThreadColdData) ==
                0);
  static_assert(sizeof(ThreadColdData) <=
                sizeof((thread_t *)0)->junction_cold_state_buf);

  bool IsStopped() const;

  // Called from the signal handler when responding to a SIGSTOP.
  void StopWait(int rax);

  // Called by a holder of a ThreadRef when the ref count hits 0.
  static void DestroyThread(Thread *th);

  // Safety check for functions that can only be called by the owning thread
  // when in interrupt or syscall context.
  inline void DebugSafetyCheck() const {
    if (IsStopped()) return;
    // Newly created thread doesn't require safety check.
    if (GetCaladanThread()->ready_tsc == 0) return;
    // The function should only be called by the owning thread.
    assert(GetCaladanThread() == thread_self());
    // The returned trapframe is only valid during a syscall (or until the
    // code has switched off of the syscall stack).
    assert(in_kernel() || rsp_on_syscall_stack());
  }

  inline KernelSignalTf &CastTfToKernelSig() const {
    if constexpr (is_debug_build())
      return dynamic_cast_guarded<KernelSignalTf &>(*cur_trapframe_);
    return reinterpret_cast<KernelSignalTf &>(*cur_trapframe_);
  }

  // Hot items
  std::shared_ptr<Process> proc_;  // the process this thread is associated with
  const pid_t tid_;                // the thread identifier

  Trapframe *cur_trapframe_;

  // Wrapper around entry trapframe pointer.
  FunctionCallTf fcall_tf;
};

// Simple shared pointer-like object to allow references to a Thread without
// holding its Process's lock.
class ThreadRef {
 public:
  explicit ThreadRef() : th_(nullptr) {}
  Thread *get() { return th_; }
  Thread *operator->() { return th_; }
  Thread *operator*() { return th_; }
  explicit operator bool() const noexcept { return th_ != nullptr; }
  ~ThreadRef() {
    if (!th_) return;
    if (--th_->cold().ref_count_ > 0) return;
    Thread::DestroyThread(th_);
  }

  // Allow move.
  ThreadRef(ThreadRef &&o) noexcept : th_(std::exchange(o.th_, nullptr)) {}
  ThreadRef &operator=(ThreadRef &&o) noexcept {
    th_ = std::exchange(o.th_, nullptr);
    return *this;
  }

  // Allow copy.
  ThreadRef(const ThreadRef &o) : th_(o.th_) {
    if (th_) th_->cold().ref_count_ += 1;
  }

  ThreadRef &operator=(const ThreadRef &o) {
    th_ = o.th_;
    if (th_) th_->cold().ref_count_ += 1;
    return *this;
  }

 private:
  friend class Thread;
  ThreadRef(Thread *th) : th_(th) { th_->cold().ref_count_ += 1; }
  Thread *th_;
};

inline ThreadRef Thread::get_ref() { return ThreadRef(this); }

// Make sure that Caladan's thread def has enough room for the Thread class
static_assert(offsetof(thread_t, junction_tstate_buf) % alignof(Thread) == 0);
static_assert(sizeof(Thread) <= sizeof((thread_t *)0)->junction_tstate_buf);

// Process is a UNIX process object.
class Process : public std::enable_shared_from_this<Process> {
 public:
  // Constructor for init process
  Process(pid_t pid, std::shared_ptr<MemoryMap> &&mm)
      : pid_(pid),
        sid_(pid),
        pgid_(pid),
        fs_(FSRoot::GetGlobalRoot()),
        mem_map_(std::move(mm)),
        parent_(nullptr) {
    RegisterProcess(*this);
  }
  // Constructor for all other processes
  Process(pid_t pid, std::shared_ptr<MemoryMap> mm, FileTable &ftbl,
          rt::ThreadWaker &&w, std::shared_ptr<Process> parent, pid_t pgid,
          const FSRoot &fs, pid_t sid)
      : pid_(pid),
        sid_(sid),
        pgid_(pgid),
        vfork_waker_(std::move(w)),
        file_tbl_(ftbl),
        fs_(fs),
        mem_map_(std::move(mm)),
        parent_(std::move(parent)) {
    RegisterProcess(*this);
  }
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
  [[nodiscard]] pid_t get_sid() const { return sid_; }
  [[nodiscard]] pid_t get_pgid() const { return pgid_; }
  [[nodiscard]] pid_t get_ppid() const {
    if (parent_) return parent_->get_pid();
    return 1;
  }

  [[nodiscard]] bool is_session_leader() const { return sid_ == pid_; }
  [[nodiscard]] bool is_process_group_leader() const { return pgid_ == pid_; }

  Status<void> JoinProcessGroup(pid_t pgid);
  Status<pid_t> BecomeSessionLeader();

  [[nodiscard]] bool in_vfork_preexec() const { return !!vfork_waker_; }
  [[nodiscard]] FileTable &get_file_table() { return file_tbl_; }
  [[nodiscard]] MemoryMap &get_mem_map() { return *mem_map_; }
  [[nodiscard]] SignalTable &get_signal_table() { return signal_tbl_; }
  [[nodiscard]] SignalQueue &get_signal_queue() { return shared_sig_q_; }
  [[nodiscard]] rlimit get_limit_nofile() const { return limit_nofile_; }
  [[nodiscard]] bool exited() const { return access_once(exited_); }
  [[nodiscard]] ITimer &get_itimer() { return it_real_; }
  [[nodiscard]] bool is_stopped() const { return stopped_gen_ % 2 == 1; }
  [[nodiscard]] bool is_fully_stopped() const {
    return is_stopped() && stopped_count_ == thread_map_.size();
  }
  [[nodiscard]] FSRoot &get_fs() { return fs_; }
  [[nodiscard]] procfs::ProcFSData &get_procfs() { return procfs_data_; }

  void set_limit_nofile(const rlimit *rlim) {
    limit_nofile_.rlim_cur = rlim->rlim_cur;
    limit_nofile_.rlim_max = rlim->rlim_max;
  }

  // Create a vforked process from this one.
  Status<std::shared_ptr<Process>> CreateProcessVfork(rt::ThreadWaker &&w);

  Status<Thread *> CreateThreadMain(const Credential &cred);
  Status<Thread *> CreateThread(const Credential &cred);
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
    if (si.si_signo == SIGCONT) {
      JobControlContinue();
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
    if (unlikely(si.si_signo == SIGCONT)) {
      JobControlContinue();
      return {};
    }

    Status<ThreadRef> tmp = FindThread(tid);
    if (!tmp) return MakeError(tmp);
    ThreadRef &th = *tmp;
    if (th->get_sighand().EnqueueSignal(si)) th->SendIpi();
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

  // Find a process for a given pid. Returns null if not found.
  static std::shared_ptr<Process> Find(pid_t pid) {
    rt::SpinGuard g(pid_map_lock_);
    auto it = pid_to_proc_.find(pid);
    if (it == pid_to_proc_.end()) return {};

    // Might be racing with Process destructor, ensure that ref count has not
    // already hit 0.
    return it->second->weak_from_this().lock();
  }

  Status<ThreadRef> FindThread(pid_t tid) {
    rt::SpinGuard g(child_thread_lock_);
    auto it = thread_map_.find(tid);
    if (it == thread_map_.end()) return MakeError(ESRCH);
    return it->second->get_ref();
  }

  Status<ThreadRef> GetFirstThread() {
    rt::SpinGuard g(child_thread_lock_);
    auto it = thread_map_.begin();
    if (it == thread_map_.end()) return MakeError(ESRCH);
    return it->second->get_ref();
  }

  // Called by threads to wait for SIGCONT. This call must occur inside of a
  // system call, and GetSyscallFrame() must be contain a trapframe that is
  // ready to be restored.
  void ThreadStopWait();

  Status<void> WaitForFullStop();
  Status<void> WaitForNthStop(size_t stopcount);
  void KillThreadsAndWait();

  // mark all threads as ready to run
  void RunThreads() {
    rt::ScopedLock g(child_thread_lock_);
    stopped_gen_ = 2;
    for (const auto &[pid, th] : thread_map_) {
      bool wake_at_head = pid == first_wake_th_;
      th->ThreadReady(wake_at_head);
    }
  }

  void SetCwd(std::shared_ptr<IDir> new_cwd) {
    rt::SpinGuard g(fs_lock_);
    fs_.SetCwd(std::move(new_cwd));
  }

  [[nodiscard]] Duration GetRuntime() {
    Duration d(0);
    rt::ScopedLock g(child_thread_lock_);
    for (const auto &[_pid, th] : thread_map_) d += th->GetRuntime();
    return d + accumulated_runtime_;
  }

  // Run a function for each process in the system.
  template <typename Func>
  static void ForEachProcess(Func func) {
    pid_map_lock_.Lock();
    std::shared_ptr<Process> procs[pid_to_proc_.size()];
    size_t cnt = 0;
    for (const auto &[pid, proc] : pid_to_proc_) {
      std::shared_ptr<Process> lck = proc->weak_from_this().lock();
      if (!lck || lck->exited()) continue;
      procs[cnt++] = std::move(lck);
    }
    pid_map_lock_.Unlock();
    for (size_t i = 0; i < cnt; i++) func(*procs[i].get());
  }

  // Run a function for each thread in this process. The function will be called
  // with a spinlock held and preemption disabled, so the function should not
  // block.
  template <typename F>
  void ForEachThread(F func) {
    rt::SpinGuard g(child_thread_lock_);
    for (const auto &[pid, th] : thread_map_) func(*th);
  }

  void JobControlStop(bool user_sig = false) {
    rt::ScopedLock g(child_thread_lock_);
    if (is_stopped()) return;
    stopped_gen_ += 1;
    SignalAllThreads(SIGSTOP);
    if (user_sig) stop_cnt_++;
  }

  void JobControlContinue() {
    rt::ScopedLock g(child_thread_lock_);
    if (!is_stopped()) return;
    stopped_gen_ += 1;
    stopped_threads_.WakeAll();
    NotifyParentWait(kWaitableContinued);
  }

 private:
  friend class cereal::access;

  void SignalAllThreads(int signo) {
    assert(child_thread_lock_.IsHeld());
    for (const auto &[pid, th] : thread_map_)
      if (th->get_sighand().SharedSignalNotifyCheck(signo)) th->SendIpi();
  }

  void FindThreadForSignal(int signo) {
    assert(child_thread_lock_.IsHeld());
    // TODO: add logic to find a thread that hasn't blocked this signal (and
    // ideally is waiting). For now, just signal all threads.
    SignalAllThreads(signo);
  }

  // Places a signal into the Process-wide signal queue and sends an IPI to a
  // thread to deliver it. May also notify a parent if this signal changes this
  // process's waitable state. Takes ownership of @lock, releasing it before
  // sending IPIs to threads.
  void SignalLocked(rt::UniqueLock<rt::Spin> &&lock, const siginfo_t &si) {
    assert(!!lock);
    assert(si.si_signo != SIGCONT);
    bool needs_ipi = shared_sig_q_.Enqueue(si);
    if (si.si_signo == SIGCHLD) child_waiters_.WakeAll();
    lock.Unlock();

    rt::ScopedLock g(child_thread_lock_);
    if (si.si_signo == SIGKILL) {
      stopped_gen_ = 0;
      stopped_threads_.WakeAll();
      SignalAllThreads(SIGKILL);
    } else if (needs_ipi)
      FindThreadForSignal(si.si_signo);
  }

  // Constructor for deserialization
  // TODO(cereal): FIX fsroot
  template <class Archive>
  Process(pid_t pid, Archive &ar)
      : pid_(pid),
        fs_(FSRoot::GetGlobalRoot()),
        signal_tbl_(DeferInit),
        stopped_gen_(1) {
    RegisterProcess(*this);

    ar(pgid_, sid_, parent_, file_tbl_, mem_map_, limit_nofile_, signal_tbl_,
       shared_sig_q_, child_procs_, wait_state_, wait_status_, it_real_.get());

    std::string cwd;
    ar(cwd);
    auto ret = LookupDirEntry(FSRoot::GetGlobalRoot(), cwd);
    if (unlikely(!ret)) throw std::runtime_error("bad lookup for cwd!");
    fs_.SetCwd(std::move(*ret));

    AcquirePid(pid_, pgid_, sid_);
  }

  template <class Archive>
  void save(Archive &ar) const {
    if (!is_stopped() || stopped_count_ != thread_map_.size())
      throw std::runtime_error("save attempted without fully stopped process.");
    if (exited_ || doing_exec_ || exec_waker_ || vfork_waker_ || child_waiters_)
      throw std::runtime_error("bad process state for snapshot");

    ar(pid_, pgid_, sid_, parent_, file_tbl_, mem_map_, limit_nofile_,
       signal_tbl_, shared_sig_q_, child_procs_, wait_state_, wait_status_,
       it_real_.get());

    Status<std::string> cwd = fs_.get_cwd_ent()->GetPathStr();
    if (!cwd) throw std::runtime_error("stale cwd during snapshot");
    ar(*cwd);

    ar(thread_map_.size(), GetLastBlockedTid(0));
    for (const auto &[pid, th] : thread_map_) {
      ar(pid);
      th->DoSave(ar);
    }
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<Process> &construct) {
    pid_t pid;
    ar(pid);
    construct(pid, ar);

    size_t n_threads;
    pid_t first_wake_th;
    ar(n_threads, first_wake_th);
    for (size_t idx = 0; idx < n_threads; idx++) {
      thread_t *th = thread_create(nullptr, 0);
      if (unlikely(!th)) {
        LOG(ERR) << "failed to allocate caladan thread";
        return;
      }

      pid_t tid;
      ar(tid);

      AcquirePid(tid);

      Thread *tstate = reinterpret_cast<Thread *>(th->junction_tstate_buf);
      new (tstate) Thread(construct->shared_from_this(), tid, ar);
      tstate->mark_enter_kernel();

      th->junction_thread = true;
      construct->thread_map_[tstate->get_tid()] = tstate;
    }

    if (!construct->parent_) SetInitProc(construct->shared_from_this());
    construct->first_wake_th_ = first_wake_th;
  }

  const pid_t pid_;         // the process identifier
  pid_t sid_;               // session ID
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

  // Wake this blocked thread that is waiting for the vfork thread to exec().
  rt::ThreadWaker vfork_waker_;

  //
  // Per-process kernel subsystems
  //

  // File descriptor table
  FileTable file_tbl_;
  FSRoot fs_;
  rt::Spin fs_lock_;

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
  size_t stopped_gen_{0};
  size_t stop_cnt_{0};

  // Protected by parent_'s shared_sig_q_lock_
  std::shared_ptr<Process> parent_;
  unsigned int wait_state_{kNotWaitable};
  int wait_status_;

  // Timers
  ITimer it_real_{*this};

  // Counters
  Duration accumulated_runtime_{0};  // Time from exited threads.

  // Procfs entries.
  procfs::ProcFSData procfs_data_;

  // First thread to wake after restore.
  pid_t first_wake_th_;

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

inline constexpr std::pair<idtype_t, id_t> PidtoId(pid_t pid) {
  if (pid < -1) return {P_PGID, -pid};
  if (pid == -1) return {P_ALL, 0};
  if (pid == 0) return {P_PGID, 0};
  return {P_PID, pid};
}

}  // namespace junction
