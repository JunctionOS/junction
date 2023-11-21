// strace.h - support for strace.

#pragma once

#include "junction/bindings/log.h"
#include "junction/kernel/proc.h"

namespace junction {

// Log a message that is prefixed with the PID and TID
#define PLOG(level) \
  LOG(level) << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] "

template <typename... Args>
void LogSyscall(long retval, std::string_view name, Args... args) {
  std::stringstream ss;
  ss << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] ";
  ss << name << "(";
  [[maybe_unused]] size_t i = 0;

  (
      [&ss, &i, n = sizeof...(args)](auto arg) {
        ss << arg;
        if (++i != n) ss << ", ";
      }(args),
      ...);

  ss << ") = " << retval;
  LOG(INFO) << ss.str();
}

template <typename... Args>
void LogSyscall(std::string_view name, Args... args) {
  std::stringstream ss;

  ss << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] ";
  ss << name << "(";
  [[maybe_unused]] size_t i = 0;

  (
      [&](auto arg) {
        ss << arg;
        if (++i != sizeof...(args)) ss << ", ";
      }(args),
      ...);

  ss << ")";
  LOG(INFO) << ss.str();
}

void LogSignal(const siginfo_t &info);

}  // namespace junction
