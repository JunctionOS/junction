// proc.h - the process abstraction

#pragma once

extern "C" {
#include <sys/resource.h>
#include <sys/types.h>
#include <ucontext.h>
}

#include <memory>

#include "junction/base/uid.h"
#include "junction/kernel/file.h"
#include "junction/kernel/mm.h"
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

constexpr size_t kSigSetSizeBytes = 8;
constexpr rlim_t kDefaultNoFile = 8192;

class Process;

// Thread is a UNIX thread object.
class Thread {
 public:
  Thread(Process *proc, pid_t tid) : proc_(proc), tid_(tid) {}
  ~Thread() = default;

  Thread(Thread &&) = delete;
  Thread &operator=(Thread &&) = delete;
  Thread(const Thread &) = delete;
  Thread &operator=(const Thread &) = delete;

  [[nodiscard]] pid_t get_tid() const { return tid_; }
  [[nodiscard]] Process &get_process() const { return *proc_; }
  [[nodiscard]] uint32_t *get_child_tid() const { return child_tid_; }
  [[nodiscard]] kernel_sigset_t get_sigset() const { return cur_sigset_; }
  void set_child_tid(uint32_t *tid) { child_tid_ = tid; }
  void set_sigset(kernel_sigset_t sigset) { cur_sigset_ = sigset; }

 private:
  Process *proc_;               // the process this thread is associated with
  uint32_t *child_tid_;         // Used for clone3/exit
  const pid_t tid_;             // the thread identifier
  kernel_sigset_t cur_sigset_;  // blocked signals
};

// Make sure that Caladan's thread def has enough room for the Thread class
static_assert(sizeof(Thread) <= sizeof((thread_t *)0)->junction_tstate_buf);

// Process is a UNIX process object.
class Process {
 public:
  Process(pid_t pid, void *base, size_t len)
      : pid_(pid), mem_map_(std::make_shared<MemoryMap>(base, len)) {}
  Process(pid_t pid, std::shared_ptr<MemoryMap> mm, FileTable &ftbl,
          std::optional<rt::ThreadWaker> w = {})
      : pid_(pid),
        vfork_waker_(std::move(w)),
        file_tbl_(ftbl),
        mem_map_(std::move(mm)) {}
  ~Process() = default;

  Process(Process &&) = delete;
  Process &operator=(Process &&) = delete;
  Process(const Process &) = delete;
  Process &operator=(const Process &) = delete;

  [[nodiscard]] pid_t get_pid() const { return pid_; }
  [[nodiscard]] FileTable &get_file_table() { return file_tbl_; }
  [[nodiscard]] MemoryMap &get_mem_map() { return *mem_map_; }
  [[nodiscard]] rlimit get_limit_nofile() const { return limit_nofile_; }
  void set_limit_nofile(const rlimit *rlim) {
    limit_nofile_.rlim_cur = rlim->rlim_cur;
    limit_nofile_.rlim_max = rlim->rlim_max;
  }

  Thread &CreateThread(thread_t *th);
  Thread &CreateTestThread();

 private:
  const pid_t pid_;     // the process identifier
  int xstate_;          // exit state
  bool killed_{false};  // If non-zero, the process has been killed
  rlimit limit_nofile_{kDefaultNoFile,
                       kDefaultNoFile};  // current rlimit for RLIMIT_NOFILE

  // Wake this blocked thread that is waiting for the vfork thread to exec().
  std::optional<rt::ThreadWaker> vfork_waker_;

  //
  // Per-process kernel subsystems
  //

  // File descriptor table
  FileTable file_tbl_;
  // Memory management
  std::shared_ptr<MemoryMap> mem_map_;
};

// Create a new process.
Status<std::unique_ptr<Process>> CreateProcess();

// mythread returns the Thread object for the running thread.
// Behavior is undefined if the running thread is not part of a process.
inline Thread &mythread() {
  thread_t *th = thread_self();
  Thread *ts = reinterpret_cast<Thread *>(th->junction_tstate_buf);
  return *reinterpret_cast<Thread *>(ts);
}

// myproc returns the Process object for the running thread.
// Behavior is undefined if the running thread is not part of a process.
inline Process &myproc() { return mythread().get_process(); }

}  // namespace junction
