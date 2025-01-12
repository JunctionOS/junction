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

template <typename U>
inline void PrintList(const U &array, rt::Logger &ss) {
  ss << "[";
  int cnt = 0;
  for (const auto &el : array) {
    if (cnt++ != 0) {
      ss << ", ";
    }
    ss << el;
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

#define DECLARE_STRACE_TYPE(type_name) \
  enum class type_name : int {};       \
  void PrintArg(int fd, type_name, rt::Logger &ss);

DECLARE_STRACE_TYPE(AtFD);
DECLARE_STRACE_TYPE(ProtFlag);
DECLARE_STRACE_TYPE(MMapFlag);
DECLARE_STRACE_TYPE(CloneFlag);
DECLARE_STRACE_TYPE(EpollOp);
DECLARE_STRACE_TYPE(OpenFlag);
DECLARE_STRACE_TYPE(SignalNumber);
DECLARE_STRACE_TYPE(MAdviseHint)
DECLARE_STRACE_TYPE(FutexOp)
DECLARE_STRACE_TYPE(IoctlOp)
DECLARE_STRACE_TYPE(FcntlOp)
DECLARE_STRACE_TYPE(SocketDomain)
DECLARE_STRACE_TYPE(SocketType)
DECLARE_STRACE_TYPE(MessageFlag)

void PrintArg(int *fds, FDPair *, rt::Logger &ss);

inline void PrintArg(const std::vector<std::string_view> &arg,
                     const std::vector<std::string_view> &, rt::Logger &ss) {
  PrintList(arg, ss);
}

void PrintArg(const struct sockaddr *addr, rt::Logger &ss);

template <typename U>
inline void PrintArg(struct timespec *t, U, rt::Logger &ss) {
  if (!t) {
    ss << "NULL";
    return;
  }
  ss << "{tv_sec=" << t->tv_sec << ", tv_nsec=" << t->tv_nsec << "}";
}

template <typename U>
inline void PrintArg(const struct sockaddr *addr, U, rt::Logger &ss) {
  PrintArg(addr, ss);
}

template <typename U>
inline void PrintArg(struct sockaddr *addr, U, rt::Logger &ss) {
  PrintArg(addr, ss);
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

template <typename... Args>
void LogSyscallDirect(long retval, std::string_view name, Args... args) {
  rt::Logger logger(LOG_INFO);
  if (likely(IsJunctionThread()))
    logger << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] ";
  logger << name << "(";
  [[maybe_unused]] size_t i = 0;

  (
      [&logger, &i, n = sizeof...(args)](auto arg) {
        strace::PrintArg(arg, arg, logger);
        if (++i != n) logger << ", ";
      }(args),
      ...);

  logger << ") = " << retval;
  if ((long)retval < 0) logger << " [" << Error(-((long)retval)) << "]";
}

template <typename... Args>
void LogSyscallDirect(std::string_view name, Args... args) {
  rt::Logger logger(LOG_INFO);
  if (likely(IsJunctionThread()))
    logger << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] ";
  logger << name << "(";
  [[maybe_unused]] size_t i = 0;

  (
      [&](auto arg) {
        strace::PrintArg(arg, arg, logger);
        if (++i != sizeof...(args)) logger << ", ";
      }(args),
      ...);

  logger << ")";
}

inline void LogSyscall(std::string_view name) {
  rt::Logger logger(LOG_INFO);
  logger << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] ";
  logger << name << "()";
}

void LogSignal(const siginfo_t &info);

}  // namespace junction
