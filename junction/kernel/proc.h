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
#include "junction/kernel/mm.h"
#include "junction/kernel/signal.h"
#include "junction/limits.h"

namespace junction {

// Note:
// glibc uses a larger sigset_t size (1024 bits) than Linux kernel (64 bits).
// We follow the Linux kernel.
//
// Sources:
//  https://unix.stackexchange.com/questions/399342/why-is-sigset-t-in-glibc-musl-128-bytes-large-on-64-bit-linux/399356#399356
//  https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/signal.h#L25
struct kernel_sigset_t {
  unsigned long sig;
};

inline constexpr size_t kSigSetSizeBytes = 8;
inline constexpr rlim_t kDefaultNoFile = 8192;

class Process;

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
  [[nodiscard]] kernel_sigset_t get_sigset() const { return cur_sigset_; }
  [[nodiscard]] bool needs_interrupt() const {
    return sig_pending_.load(std::memory_order_acquire);
  }

  void set_child_tid(uint32_t *tid) { child_tid_ = tid; }
  void set_sigset(kernel_sigset_t sigset) { cur_sigset_ = sigset; }
  void set_xstate(int xstate) { xstate_ = xstate; }

  thread_t *GetCaladanThread() {
    auto *ptr =
        reinterpret_cast<decltype(thread_t::junction_tstate_buf) *>(this);
    return container_of(ptr, thread_t, junction_tstate_buf);
  }

  // Deliver an interrupt to this thread.
  void Interrupt() {
    // For now just mark signal pending
    rt::SpinGuard g(lock_);
    sig_pending_ = true;
  }

  // Called by a thread to run pending interrupts.
  void HandleInterrupt();

 private:
  std::shared_ptr<Process> proc_;  // the process this thread is associated with
  uint32_t *child_tid_;            // Used for clone3/exit
  const pid_t tid_;                // the thread identifier

  rt::Spin lock_;                 // protects sigstate, waiters, etc
  kernel_sigset_t cur_sigset_;    // blocked signals
  std::atomic_bool sig_pending_;  // has a pending signal
  int xstate_;                    // exit state
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
  [[nodiscard]] rlimit get_limit_nofile() const { return limit_nofile_; }
  [[nodiscard]] bool exited() const { return exited_; }

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

 private:
  const pid_t pid_;     // the process identifier
  int xstate_;          // exit state
  bool exited_{false};  // If true, the process has been killed
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
