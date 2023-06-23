// strace.h - support for strace.

#pragma once

#include "junction/bindings/log.h"
#include "junction/kernel/proc.h"

namespace junction {

template <class F>
void do_for(F f) {
  // Parameter pack is empty.
}

template <class F, typename First>
void do_for(F f, First first) {
  f(first, true);
  do_for(f);
}

template <class F, typename First, typename... Rest>
void do_for(F f, First first, Rest... rest) {
  f(first, false);
  do_for(f, rest...);
}

template <typename... Args>
void LogSyscall(long retval, std::string_view name, Args... args) {
  std::stringstream ss;

  ss << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] ";
  ss << name << "(";

  do_for(
      [&](auto arg, bool last) {
        ss << arg;
        if (!last) ss << ", ";
      },
      args...);

  ss << ") = " << retval;
  LOG(INFO) << ss.str();
}
}  // namespace junction
