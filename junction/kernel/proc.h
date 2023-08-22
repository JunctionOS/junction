// proc.h - the process abstraction

#pragma once

extern "C" {
#include <sys/resource.h>
#include <sys/types.h>
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

  void ThreadReady() { thread_ready(GetCaladanThread()); }

  void OnSyscallEnter() {
    access_once(in_syscall_) = true;
    if (unlikely(needs_interrupt())) HandleInterrupt(std::nullopt);
  }

  void OnSyscallLeave(long rax) {
    if (unlikely(needs_interrupt())) HandleInterrupt(rax);
    access_once(in_syscall_) = false;
    SetSyscallFrame(nullptr);
  }

  void Kill() {
    siginfo_t info;
    info.si_signo = SIGKILL;
    if (sighand_.EnqueueSignal(&info)) SendIpi();
  }

  // TODO!
  void SendIpi(){};

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
  Process(pid_t pid, std::shared_ptr<MemoryMap> &&mm)
      : pid_(pid), mem_map_(std::move(mm)) {
    all_procs.Add(1);
  }
  Process(pid_t pid, std::shared_ptr<MemoryMap> mm, FileTable &ftbl,
          rt::ThreadWaker &&w)
      : pid_(pid),
        vfork_waker_(std::move(w)),
        file_tbl_(ftbl),
        mem_map_(std::move(mm)) {
    all_procs.Add(1);
  }

  ~Process();

  Process(Process &&) = delete;
  Process &operator=(Process &&) = delete;
  Process(const Process &) = delete;
  Process &operator=(const Process &) = delete;

  [[nodiscard]] pid_t get_pid() const { return pid_; }
  [[nodiscard]] FileTable &get_file_table() { return file_tbl_; }
  [[nodiscard]] MemoryMap &get_mem_map() { return *mem_map_; }
  [[nodiscard]] SignalTable &get_signal_table() { return signal_tbl_; }
  [[nodiscard]] SignalQueue &get_signal_queue() { return shared_sig_q_; }
  [[nodiscard]] rlimit get_limit_nofile() const { return limit_nofile_; }
  [[nodiscard]] bool exited() const { return exited_; }
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
  void ThreadFinish(Thread *th);

  // Called when a process exits, will attempt to notify all threads.
  void DoExit(int status);

  static void WaitAll() { all_procs.Wait(); }

  Status<void> Signal(siginfo_t &si) {
    {
      rt::SpinGuard g(shared_sig_q_);
      shared_sig_q_.Enqueue(&si);
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
    rt::SpinGuard g(thread_map_lock_);

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

 private:
  const pid_t pid_;     // the process identifier
  int xstate_;          // exit state
  bool exited_{false};  // If true, the process has been killed

  // TODO: enforce limit
  rlimit limit_nofile_{kDefaultNoFile,
                       kDefaultNoFile};  // current rlimit for RLIMIT_NOFILE
  std::string binary_path_;

  // Wake this blocked thread that is waiting for the vfork thread to exec().
  rt::ThreadWaker vfork_waker_;

  rt::Spin thread_map_lock_;
  // TODO(jf): replace std::map with better datastructure
  std::map<pid_t, Thread *> thread_map_;

  //
  // Per-process kernel subsystems
  //

  // File descriptor table
  FileTable file_tbl_;
  // Memory mappings
  std::shared_ptr<MemoryMap> mem_map_;

  // Signal table
  SignalTable signal_tbl_;
  SignalQueue shared_sig_q_;

  // Timers
  ITimer it_real_{this};

  static rt::WaitGroup all_procs;
};

// Create a new process.
Status<std::shared_ptr<Process>> CreateProcess();

// mythread returns the Thread object for the running thread.
// Behavior is undefined if the running thread is not part of a process.
inline Thread &mythread() {
  thread_t *th = thread_self();
  auto *ts = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  return *reinterpret_cast<Thread *>(ts);
}

// myproc returns the Process object for the running thread.
// Behavior is undefined if the running thread is not part of a process.
inline Process &myproc() { return mythread().get_process(); }

}  // namespace junction
