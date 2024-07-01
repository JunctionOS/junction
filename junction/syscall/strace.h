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
struct FDPair {};
enum class AtFD : int {};
enum class ProtFlag : int {};
enum class MMapFlag : int {};
enum class OpenFlag : int {};
enum class SignalNumber : int {};
enum class MAdviseHint : int {};

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

// Override: print char *s that are annotated as PathNames.
void PrintArg(const char *arg, PathName *, rt::Logger &ss);

// Don't print const char * args without a PathName annotation.
template <typename T>
inline void PrintArg(const char *arg, T, rt::Logger &ss) {
  ss << (const void *)arg;
}

void PrintArg(int fd, AtFD, rt::Logger &ss);
void PrintArg(int prot, ProtFlag, rt::Logger &ss);
void PrintArg(int flags, MMapFlag, rt::Logger &ss);
void PrintArg(int *fds, FDPair *, rt::Logger &ss);
void PrintArg(int flags, OpenFlag, rt::Logger &ss);
void PrintArg(int signo, SignalNumber, rt::Logger &ss);
void PrintArg(int advice, MAdviseHint, rt::Logger &ss);

template <typename U>
inline void PrintArg(struct timespec *t, U, rt::Logger &ss) {
  if (!t) {
    ss << "NULL";
    return;
  }
  ss << "{tv_sec=" << t->tv_sec << ", tv_nsec=" << t->tv_nsec << "}";
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
  if ((long)retval < 0) logger << " [" << Error(-((long)retval)) << "]";
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
