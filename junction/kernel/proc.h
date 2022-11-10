// proc.h - the process abstraction

#pragma once

#include "junction/kernel/file.h"

namespace junction {

struct Proc {
  pid_t pid;           // process identifier number
  int xstate;          // exit state
  bool killed{false};  // If non-zero, the process has been killed
  FileTable ftable;    // file descriptor table
};

inline struct Proc *myproc() {
  // TODO(amb): get this from caladan's thread_t.
  return nullptr;
}

pid_t usys_getpid() {
  // TODO(girfan): return value from myproc().
  return 0;
}

}  // namespace junction
