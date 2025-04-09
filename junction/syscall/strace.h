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

#define DECLARE_STRACE_TYPE(type_name, type_type) \
  enum class type_name : int {};                  \
  void PrintArg(type_type, type_name, rt::Logger &ss);

DECLARE_STRACE_TYPE(AtFD, int);
DECLARE_STRACE_TYPE(ProtFlag, int);
DECLARE_STRACE_TYPE(MMapFlag, int);
DECLARE_STRACE_TYPE(CloneFlag, unsigned long);
DECLARE_STRACE_TYPE(EpollOp, int);
DECLARE_STRACE_TYPE(OpenFlag, int);
DECLARE_STRACE_TYPE(SignalNumber, int);
DECLARE_STRACE_TYPE(MAdviseHint, int)
DECLARE_STRACE_TYPE(FutexOp, int)
DECLARE_STRACE_TYPE(IoctlOp, unsigned int)
DECLARE_STRACE_TYPE(FcntlOp, unsigned int)
DECLARE_STRACE_TYPE(SocketDomain, int)
DECLARE_STRACE_TYPE(SocketType, int)
DECLARE_STRACE_TYPE(MessageFlag, int)
DECLARE_STRACE_TYPE(PrctlOp, long)
DECLARE_STRACE_TYPE(SigProcMaskOp, int)
DECLARE_STRACE_TYPE(WaitOptions, int);

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

inline void PrintArg(struct timeval tv, rt::Logger &ss) {
  ss << "{tv_sec=" << tv.tv_sec << ", tv_usec=" << tv.tv_usec << "}";
}

template <typename U>
inline void PrintArg(const struct itimerval *it, U, rt::Logger &ss) {
  if (!it) {
    ss << "NULL";
    return;
  }
  ss << "{it_interval=";
  PrintArg(it->it_interval, ss);
  ss << ", it_value=";
  PrintArg(it->it_value, ss);
  ss << "}";
}

template <typename U>
inline void PrintArg(struct itimerval *it, U x, rt::Logger &ss) {
  const struct itimerval *cit = it;
  PrintArg(cit, x, ss);
}

template <typename U>
inline void PrintArg(const struct sockaddr *addr, U, rt::Logger &ss) {
  PrintArg(addr, ss);
}

template <typename U>
inline void PrintArg(struct sockaddr *addr, U, rt::Logger &ss) {
  PrintArg(addr, ss);
}

template <typename U>
inline void PrintArg(cap_user_header_t hdrp, U, rt::Logger &ss) {
  ss << "{" << hdrp->version << ", " << hdrp->pid << "}";
}

template <typename U>
inline void PrintArg(idtype_t idt, U, rt::Logger &ss) {
  if (idt == P_PID)
    ss << "P_PID";
  else if (idt == P_PIDFD)
    ss << "P_PIDFD";
  else if (idt == P_PGID)
    ss << "P_PGID";
  else if (P_ALL)
    ss << "P_ALL";
  else
    ss << idt;
}

void PrintArg(const cap_user_data_t, rt::Logger &ss);

void PrintArg(const sigset_t *sigmask, rt::Logger &ss);

template <typename U>
inline void PrintArg(const sigset_t *mask, U, rt::Logger &ss) {
  PrintArg(mask, ss);
}

template <typename U>
inline void PrintArg(sigset_t *mask, U, rt::Logger &ss) {
  PrintArg(mask, ss);
}

template <typename U>
inline void PrintArg(const cap_user_data_t datap, U, rt::Logger &ss) {
  PrintArg(datap, ss);
}

template <int N, typename Ret, typename... UsysArgs, typename ArgT>
constexpr void UnpackArgs(rt::Logger &ss, Ret (*fn)(UsysArgs...), ArgT &args,
                          bool last = true) {
  if constexpr (N > 0) UnpackArgs<N - 1>(ss, fn, args, false);
  using ArgType = std::tuple_element_t<N, std::tuple<UsysArgs...>>;
  PrintArg(((const ArgType)std::get<N>(args)), std::get<N>(args), ss);
  if (!last) ss << ", ";
}

std::string GetFcntlName(int cmd);

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
