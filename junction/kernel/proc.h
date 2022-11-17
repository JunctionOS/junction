// proc.h - the process abstraction

#pragma once

extern "C" {
#include <sys/types.h>
}

#include "junction/kernel/file.h"
#include "junction/kernel/usys.h"

namespace junction {

class Proc {
 public:
  pid_t pid;           // process identifier number
  int xstate;          // exit state
  bool killed{false};  // If non-zero, the process has been killed
  FileTable ftable;    // file descriptor table
};

inline Proc* myproc() {
  // TODO(amb): get this from caladan's thread_t.
  static Proc* _myproc = new Proc();
  return _myproc;
}

}  // namespace junction
