// strace.h - support for strace.

#pragma once

#include "junction/bindings/log.h"
#include "junction/kernel/proc.h"

#ifndef P_PIDFD
#define P_PIDFD 3
#endif

namespace junction {

// Log a message that is prefixed with the PID and TID
#define PLOG(level) \
  LOG(level) << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] "

namespace strace {

struct PathName {};
struct FDPair {};

struct SyscallCtx {
  std::tuple<long, long, long, long, long, long> args;
  long sysn;
  std::optional<std::stringstream> arg_strs[6];
  std::optional<long> retval;
};

template <typename U>
inline void PrintArg(const char **array, U, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
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
inline void PrintArg(const T arg, const U, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  ss << arg;
}

// Override: don't print arguments with type char *.
template <typename U>
inline void PrintArg(char *arg, U, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  ss << (void *)arg;
}

// Override: print char *s that are annotated as PathNames.
void PrintArg(const char *arg, PathName *, rt::Logger &ss, SyscallCtx &ctx);

// Don't print const char * args without a PathName annotation.
template <typename T>
inline void PrintArg(const char *arg, T, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  ss << (const void *)arg;
}

#define DECLARE_STRACE_TYPE(type_name, type_type) \
  enum class type_name : int {};                  \
  void PrintArg(type_type, type_name, rt::Logger &ss, SyscallCtx &ctx);

extern bool PrintFlagArr(const std::map<int, std::string> &map, int flags,
                         rt::Logger &ss);

#define DECLARE_STRACE_FLAG_ARR(type_name, type_type, map_name)    \
  enum class type_name : int {};                                   \
  extern const std::map<int, std::string> map_name;                \
  inline void PrintArg(type_type flags, type_name, rt::Logger &ss, \
                       [[maybe_unused]] SyscallCtx &ctx) {         \
    PrintFlagArr(map_name, flags, ss);                             \
  }

DECLARE_STRACE_TYPE(SockoptLevel, int);

DECLARE_STRACE_TYPE(AtFD, int);
DECLARE_STRACE_TYPE(ProtFlag, int);
DECLARE_STRACE_FLAG_ARR(MMapFlag, int, mmap_flags);
DECLARE_STRACE_FLAG_ARR(CloneFlag, unsigned long, clone_flags);
DECLARE_STRACE_TYPE(EpollOp, int);
DECLARE_STRACE_TYPE(OpenFlag, int);
DECLARE_STRACE_TYPE(SignalNumber, int);
DECLARE_STRACE_TYPE(MAdviseHint, int)
DECLARE_STRACE_TYPE(FutexOp, int)
DECLARE_STRACE_TYPE(IoctlOp, unsigned int)
DECLARE_STRACE_TYPE(FcntlOp, unsigned int)
DECLARE_STRACE_TYPE(SocketDomain, int)
DECLARE_STRACE_TYPE(SocketType, int)
DECLARE_STRACE_FLAG_ARR(MessageFlag, int, msg_flags);
DECLARE_STRACE_TYPE(PrctlOp, long)
DECLARE_STRACE_TYPE(SigProcMaskOp, int)
DECLARE_STRACE_FLAG_ARR(WaitOptions, int, wait_flags);
DECLARE_STRACE_FLAG_ARR(StatxMask, unsigned int, statx_mask_flags);
DECLARE_STRACE_FLAG_ARR(AtFlag, int, at_flags);

inline void PrintArg(CloneFlag flags, CloneFlag, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  PrintFlagArr(clone_flags, static_cast<int>(flags), ss);
}

void PrintArg(int *fds, FDPair *, rt::Logger &ss, SyscallCtx &ctx);

inline void PrintArg(const std::vector<std::string_view> &arg,
                     const std::vector<std::string_view> &, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  PrintList(arg, ss);
}

void PrintArg(const struct sockaddr *addr, rt::Logger &ss);

template <typename Logger>
inline void PrintArg(const struct timespec *t, Logger &ss) {
  if (!t) {
    ss << "NULL";
    return;
  }
  ss << "{tv_sec=" << t->tv_sec << ", tv_nsec=" << t->tv_nsec << "}";
}

template <typename U>
inline void PrintArg(struct timespec *t, U, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  PrintArg(t, ss);
}

template <typename Logger>
inline void PrintArg(struct timeval tv, Logger &ss) {
  ss << "{tv_sec=" << tv.tv_sec << ", tv_usec=" << tv.tv_usec << "}";
}

template <typename U>
inline void PrintArg(const struct itimerval *it, U, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
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
inline void PrintArg(struct itimerval *it, U x, rt::Logger &ss,
                     SyscallCtx &ctx) {
  const struct itimerval *cit = it;
  PrintArg(cit, x, ss, ctx);
}

template <typename U>
inline void PrintArg(const struct sockaddr *addr, U, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  PrintArg(addr, ss);
}

template <typename U>
inline void PrintArg(struct sockaddr *addr, U, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  PrintArg(addr, ss);
}

template <typename U>
inline void PrintArg(cap_user_header_t hdrp, U, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  ss << "{" << hdrp->version << ", " << hdrp->pid << "}";
}

template <typename U>
inline void PrintArg(struct stat *stat, U, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  ss << "{st_mode=";
  if ((stat->st_mode & kTypeMask) == kTypeRegularFile) ss << "S_IFREG";
  if ((stat->st_mode & kTypeMask) == kTypeDirectory) ss << "S_IFDIR";
  if ((stat->st_mode & kTypeMask) == kTypeCharacter) ss << "S_IFCHR";
  if ((stat->st_mode & kTypeMask) == kTypeBlock) ss << "S_IFBLK";
  if ((stat->st_mode & kTypeMask) == kTypeFIFO) ss << "S_IFIFO";
  if ((stat->st_mode & kTypeMask) == kTypeSocket) ss << "S_IFSOCK";
  if ((stat->st_mode & kTypeMask) == kTypeSymLink) ss << "S_IFLNK";
  ss << "|0" << std::oct << (stat->st_mode & kModeMask) << std::dec;
  ss << ", st_size=" << stat->st_size << "...}";
}

template <typename U>
inline void PrintArg(idtype_t idt, U, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
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

void PrintUserCap(const cap_user_data_t, rt::Logger &ss);
void PrintSigset(const sigset_t *sigmask, rt::Logger &ss);

template <typename U>
inline void PrintArg(const sigset_t *mask, U, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  PrintSigset(mask, ss);
}

template <typename U>
inline void PrintArg(sigset_t *mask, U, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  PrintSigset(mask, ss);
}

template <typename U>
inline void PrintArg(const cap_user_data_t datap, U, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  PrintUserCap(datap, ss);
}

template <int N, typename Ret, typename... UsysArgs, typename ArgT>
constexpr void UnpackArgs(rt::Logger &ss, Ret (*fn)(UsysArgs...), ArgT &args,
                          SyscallCtx &ctx, bool last = true) {
  if constexpr (N > 0) UnpackArgs<N - 1>(ss, fn, args, ctx, false);
  if (!(ss.absorb(ctx.arg_strs[N]))) {
    using ArgType = std::tuple_element_t<N, std::tuple<UsysArgs...>>;
    PrintArg(((const ArgType)std::get<N>(args)), std::get<N>(args), ss, ctx);
  }
  if (!last) ss << ", ";
}

std::string GetFcntlName(int cmd);

struct ArrayInfo {
  void *ptr;
  size_t size;
};

bool PrintArg(struct pollfd el, rt::Logger &ss, bool first);
bool PrintArg(const struct epoll_event el, rt::Logger &ss, bool first);

template <typename U>
inline void PrintArgSpan(std::span<const U> span, rt::Logger &ss) {
  ss << "[";
  int cnt = 0;
  for (const auto &el : span) {
    if (cnt == 2) {
      ss << ", ...";
      break;
    }
    if (PrintArg(el, ss, cnt == 0)) cnt++;
  }
  ss << "]";
}

template <typename T>
inline void PrintArg(T *, ArrayInfo *arrinfo, rt::Logger &ss,
                     [[maybe_unused]] SyscallCtx &ctx) {
  // Make a span from the array info
  std::span<const T> span(reinterpret_cast<T *>(arrinfo->ptr), arrinfo->size);
  PrintArgSpan(span, ss);
}

}  // namespace strace

template <typename Ret, typename... RegisterArgs, typename UsysRet,
          typename... UsysArgs>
void LogSyscall(strace::SyscallCtx &ctx, Ret retval, std::string_view name,
                UsysRet (*fn)(UsysArgs...), RegisterArgs... args) {
  rt::Logger logger(LOG_INFO);
  logger << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] ";
  logger << name << "(";
  constexpr size_t n_args = sizeof...(UsysArgs);
  if constexpr (n_args) {
    auto args_t = std::make_tuple(args...);
    strace::UnpackArgs<n_args - 1>(logger, fn, args_t, ctx);
  }
  logger << ") = " << retval;
  if ((long)retval < 0) logger << " [" << Error(-((long)retval)) << "]";
}

template <typename... RegisterArgs, typename Ret, typename... UsysArgs>
void LogSyscall(strace::SyscallCtx &ctx, std::string_view name,
                Ret (*fn)(UsysArgs...), RegisterArgs... args) {
  rt::Logger logger(LOG_INFO);
  logger << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] ";
  logger << name << "(";
  constexpr size_t n_args = sizeof...(UsysArgs);
  if constexpr (n_args) {
    auto args_t = std::make_tuple(args...);
    strace::UnpackArgs<n_args - 1>(logger, fn, args_t, ctx);
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

  strace::SyscallCtx ctx;  // TODO:fixme.

  (
      [&logger, &i, &ctx, n = sizeof...(args)](auto arg) {
        if (!logger.absorb(ctx.arg_strs[i]))
          strace::PrintArg(arg, arg, logger, ctx);
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

  strace::SyscallCtx ctx;  // TODO:fixme.

  (
      [&](auto arg) {
        if (!logger.absorb(ctx.arg_strs[i]))
          strace::PrintArg(arg, arg, logger, ctx);
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
