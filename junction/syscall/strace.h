// strace.h - support for strace.

#pragma once

#include "junction/bindings/log.h"
#include "junction/kernel/proc.h"

namespace junction {

// Log a message that is prefixed with the PID and TID
#define PLOG(level) \
  LOG(level) << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] "

namespace strace {

struct PathName {};
enum class AtFD : int {};

template <typename U>
inline void PrintArg(const char **array, U, rt::Logger &ss) {
  ss << "[";
  int cnt = 0;
  while (*array) {
    if (cnt++ != 0) {
      ss << ", ";
    }
    ss << *array;
    array++;
  }
  ss << "]";
}

// Default: print any syscall argument using the defined type in usys.h.
template <typename T, typename U>
inline void PrintArg(const T arg, const U, rt::Logger &ss) {
  ss << arg;
}

// Override: don't print arguments with type char *.
template <typename U>
inline void PrintArg(char *arg, U, rt::Logger &ss) {
  ss << (void *)arg;
}

template <typename T>
struct is_pathname_ptr : std::is_same<std::remove_const_t<T>, PathName *> {};

template <typename T>
constexpr bool is_pathname_ptr_v = is_pathname_ptr<T>::value;

// Override: print char *s that are annotated as PathNames.
template <typename T,
          typename std::enable_if_t<is_pathname_ptr_v<T>> * = nullptr>
inline void PrintArg(const char *arg, T, rt::Logger &ss) {
  ss << "\"" << arg << "\"";
}

// Don't print const char * args without a PathName annotation.
template <typename T,
          typename std::enable_if_t<!is_pathname_ptr_v<T>> * = nullptr>
inline void PrintArg(const char *arg, T, rt::Logger &ss) {
  ss << (const void *)arg;
}

inline void PrintArg(int fd, AtFD, rt::Logger &ss) {
  if (fd == AT_FDCWD)
    ss << "AT_FDCWD";
  else
    ss << fd;
}

template <typename U>
inline void PrintArg(int fds[2], U, rt::Logger &ss) {
  ss << "[" << fds[0] << ", " << fds[1] << "]";
}

template <int N, typename Ret, typename... UsysArgs, typename ArgT>
constexpr void UnpackArgs(rt::Logger &ss, Ret (*fn)(UsysArgs...), ArgT &args,
                          bool last = true) {
  if constexpr (N > 0) UnpackArgs<N - 1>(ss, fn, args, false);
  using ArgType = std::tuple_element_t<N, std::tuple<UsysArgs...>>;
  PrintArg(((const ArgType)std::get<N>(args)), std::get<N>(args), ss);
  if (!last) ss << ", ";
}

}  // namespace strace

template <typename Ret, typename... RegisterArgs, typename UsysRet,
          typename... UsysArgs>
void LogSyscall(Ret retval, std::string_view name, UsysRet (*fn)(UsysArgs...),
                RegisterArgs... args) {
  rt::Logger logger(LOG_INFO);
  logger << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] ";
  logger << name << "(";
  constexpr size_t n_args = sizeof...(UsysArgs);
  if constexpr (n_args) {
    auto args_t = std::make_tuple(args...);
    strace::UnpackArgs<n_args - 1>(logger, fn, args_t);
  }
  logger << ") = " << retval;
}

template <typename... RegisterArgs, typename Ret, typename... UsysArgs>
void LogSyscall(std::string_view name, Ret (*fn)(UsysArgs...),
                RegisterArgs... args) {
  rt::Logger logger(LOG_INFO);
  logger << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] ";
  logger << name << "(";
  constexpr size_t n_args = sizeof...(UsysArgs);
  if constexpr (n_args) {
    auto args_t = std::make_tuple(args...);
    strace::UnpackArgs<n_args - 1>(logger, fn, args_t);
  }
  logger << ")";
}

inline void LogSyscall(std::string_view name) {
  rt::Logger logger(LOG_INFO);
  logger << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] ";
  logger << name << "()";
}

void LogSignal(const siginfo_t &info);

}  // namespace junction
