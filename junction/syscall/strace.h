// strace.h - support for strace.

#pragma once

#include "junction/bindings/log.h"
#include "junction/kernel/proc.h"

namespace junction {

template <typename... Args>
void LogSyscall(long retval, std::string_view name, Args... args) {
  std::stringstream ss;

  ss << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] ";
  ss << name << "(";
  size_t i = 0;

  (
      [&](auto arg) {
        ss << arg;
        if (++i != sizeof...(args)) ss << ", ";
      }(args),
      ...);

  ss << ") = " << retval;
  LOG(INFO) << ss.str();
}

}  // namespace junction
