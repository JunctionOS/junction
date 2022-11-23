// proc.h - the process abstraction

#pragma once

extern "C" {
#include <sys/types.h>
}

#include "junction/kernel/file.h"

namespace junction {

class Proc;
struct ThreadState {
  Proc *proc;
  uint32_t *child_tid;  // Used for clone3/exit
  pid_t tid;
};

class Proc {
 public:
  pid_t pid;           // process identifier number
  int xstate;          // exit state
  bool killed{false};  // If non-zero, the process has been killed
  FileTable ftable;    // file descriptor table

  ThreadState *ProcSetupNewThread(thread_t *th);
};

inline ThreadState *mystate() {
  return reinterpret_cast<ThreadState *>(get_uthread_specific());
}

inline Proc *myproc() {
  ThreadState *ts = mystate();

  // Temporary
  if (!ts) {
    static Proc *_myproc = new Proc();
    return _myproc;
  }

  return ts->proc;
}

}  // namespace junction
