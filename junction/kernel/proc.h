// proc.h - the process abstraction

#pragma once

extern "C" {
#include <sys/types.h>
#include <ucontext.h>
}

#include <memory>

#include "junction/kernel/file.h"
#include "junction/kernel/futex.h"

namespace junction {

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
  [[nodiscard]] Process &get_process() { return *proc_; }
  [[nodiscard]] uint32_t *get_child_tid() { return child_tid_; }
  [[nodiscard]] ucontext_t *get_tf() { return tf_; }
  void set_child_tid(uint32_t *tid) { child_tid_ = tid; }
  void set_tf(ucontext_t *tf) { tf_ = tf; }

 private:
  Process *proc_;            // the process this thread is associated with
  uint32_t *child_tid_;      // Used for clone3/exit
  pid_t tid_;                // the thread identifier
  ucontext_t *tf_{nullptr};  // non-null when signal handler is used
};

// Process is a UNIX process object.
class Process {
 public:
  Process(pid_t pid) : pid_(pid) {}
  ~Process() = default;

  Process(Process &&) = delete;
  Process &operator=(Process &&) = delete;
  Process(const Process &) = delete;
  Process &operator=(const Process &) = delete;

  [[nodiscard]] pid_t get_pid() const { return pid_; }
  [[nodiscard]] FileTable &get_file_table() { return file_tbl_; }

  Thread &CreateThread(thread_t *th);

 private:
  pid_t pid_;           // the process identifier
  int xstate_;          // exit state
  bool killed_{false};  // If non-zero, the process has been killed

  // per-process kernel subsystems
  FileTable file_tbl_;  // file descriptor table
};

// mythread returns the Thread object for the running thread.
// Behavior is undefined if the running thread is not part of a process.
inline Thread &mythread() {
  BUG_ON(!get_uthread_specific());  // TODO: change to assert.
  return *reinterpret_cast<Thread *>(get_uthread_specific());
}

// myproc returns the Process object for the running thread.
// Behavior is undefined if the running thread is not part of a process.
inline Process &myproc() { return mythread().get_process(); }

}  // namespace junction
