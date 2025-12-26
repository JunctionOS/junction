#include "junction/syscall/strace.h"

#include "junction/syscall/strace_maps.h"

extern "C" {
#include <linux/futex.h>
#include <linux/ioctl.h>
#include <linux/prctl.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
}

#include <map>

#include "junction/bindings/log.h"
#include "junction/net/socket.h"

namespace junction {

namespace strace {

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif

#ifndef PR_GET_AUXV
#define PR_GET_AUXV 0x41555856
#endif

#ifndef PR_SET_MDWE
#define PR_SET_MDWE 65
#define PR_GET_MDWE 66
#endif

void PrintEscapedString(std::span<const char> str, rt::Logger &ss) {
  if (!str.size()) {
    ss << "\"\"";
    return;
  }

  ss << "\"";
  size_t len = 0;
  const char *pos = str.data();
  while (len < std::min(str.size(), kMaxEscapedStringLen)) {
    unsigned char c = *pos++;
    if (c >= 32 && c <= 126 && c != '\\' && c != '"') {
      // Printable ASCII characters (except \ and ")
      ss << c;
    } else {
      // Escape special characters
      switch (c) {
        case '\\':
          ss << "\\\\";
          break;
        case '"':
          ss << "\\\"";
          break;
        case '\n':
          ss << "\\n";
          break;
        case '\r':
          ss << "\\r";
          break;
        case '\t':
          ss << "\\t";
          break;
        case '\f':
          ss << "\\f";
          break;
        case '\v':
          ss << "\\v";
          break;
        case '\b':
          ss << "\\b";
          break;
        case '\a':
          ss << "\\a";
          break;
        default:
          // Print non-printable chars as octal
          ss << '\\' << std::oct << std::setfill('0') << std::setw(3)
             << static_cast<unsigned int>(c) << std::dec;
      }
    }
    len++;
  }
  if (*pos) { ss << "..."; }
  ss << "\"";
}

std::string GetFcntlName(int cmd) {
  auto it = fcntls.find(cmd);
  if (it != fcntls.end()) return it->second;
  return std::to_string(cmd);
}

void PrintSigset(const sigset_t *sigmask, rt::Logger &ss) {
  if (!sigmask) {
    ss << "NULL";
    return;
  }

  uint64_t mask = *reinterpret_cast<const uint64_t *>(sigmask);

  bool done_one = false;
  ss << "{";
  for (size_t i = 0; i < kNumSignals; i++) {
    if ((mask & (1 << i)) == 0) continue;
    if (done_one) ss << ",";
    done_one = true;

    if (i < kNumSignals)
      ss << sigmap[i];
    else
      ss << "SIGRT" << i;
  }
  ss << "}";
}

void PrintIoctlReq(unsigned int request, rt::Logger &ss) {
  unsigned int dir = _IOC_DIR(request);
  unsigned int type = _IOC_TYPE(request);
  unsigned int nr = _IOC_NR(request);
  unsigned int size = _IOC_SIZE(request);

  ss << "_IOC(";

  bool printed = false;
  if (dir & _IOC_READ) {
    ss << "_IOC_READ";
    printed = true;
  }
  if (dir & _IOC_WRITE) {
    if (printed) ss << "|";
    ss << "_IOC_WRITE";
    printed = true;
  }
  if (!printed) { ss << "0"; }

  ss << ", 0x" << std::hex << type << ", 0x" << std::hex << nr << ", 0x"
     << std::hex << size << ")";
}

bool PrintValMap(const std::map<int, std::string> &map, int val, rt::Logger &ss,
                 bool print_on_miss = true) {
  auto it = map.find(val);
  if (it != map.end()) {
    ss << it->second;
    return true;
  }
  if (print_on_miss) ss << val;
  return false;
}

void PrintUserCap(const cap_user_data_t datap, rt::Logger &ss) {
  if (!datap) {
    ss << "NULL";
    return;
  }
  ss << "{effective=" << std::hex << datap->effective
     << ",permitted=" << datap->permitted
     << ",inheritable=" << datap->inheritable << "}";
}

void PrintArg(const struct sockaddr *addr, rt::Logger &ss) {
  if (!addr) {
    ss << "NULL";
    return;
  }

  if (addr->sa_family == AF_UNIX) {
    auto uin = reinterpret_cast<const sockaddr_un *>(addr);
    ss << "unix:";
    for (size_t i = 0; i < sizeof(uin->sun_path); i++) {
      if (uin->sun_path[i] == '\0') {
        if (i == 0)
          ss << "\0";
        else
          break;
      }

      if (uin->sun_path[i] < 32 || uin->sun_path[i] > 126)
        ss << "@";
      else
        ss << uin->sun_path[i];
    }
    return;
  }

  if (addr->sa_family != AF_INET) {
    ss << "{unknown_type: " << addr->sa_family << "}";
    return;
  }

  auto sin = reinterpret_cast<const sockaddr_in *>(addr);
  char str[IP_ADDR_STR_LEN];
  char *ip = ip_addr_to_str(ntoh32(sin->sin_addr.s_addr), str);

  ss << ip << ":" << ntoh16(sin->sin_port);
}

void PrintArg(int op, SocketDomain, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  PrintValMap(sock_domains, op, ss);
}

void PrintArg(int op, SocketType, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  int type = op & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
  PrintValMap(sock_types, type, ss);
  if (op & SOCK_NONBLOCK) ss << "|SOCK_NONBLOCK";
  if (op & SOCK_CLOEXEC) ss << "|SOCK_CLOEXEC";
}

void PrintArg(const struct msghdr *msg, rt::Logger &ss, SyscallCtx &ctx) {
  ss << "{msg_name=";
  PrintArg(reinterpret_cast<const struct sockaddr *>(msg->msg_name), ss);
  ss << ", msg_namelen=" << msg->msg_namelen << ", msg_iov=";

  std::span<const iovec> span(reinterpret_cast<const iovec *>(msg->msg_iov),
                              msg->msg_iovlen);
  PrintArgSpan(span, ss, ctx);
  ss << ", msg_iovlen=" << msg->msg_iovlen
     << ", msg_control=" << msg->msg_control
     << ", msg_controllen=" << msg->msg_controllen
     << ", msg_flags=" << msg->msg_flags << "}";
}

void PrintArg(int advice, MAdviseHint, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  PrintValMap(madvise_hints, advice, ss);
}

void PrintArg(int signo, SignalNumber, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  if (static_cast<size_t>(signo) <= kNumSignals)
    ss << sigmap[signo - 1];
  else
    ss << "SIGRT" << signo;
}

void PrintArg(int op, EpollOp, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  PrintValMap(epoll_ctl_ops, op, ss);
}

void PrintArg(const char *arg, PathName *, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  if (!arg)
    ss << "<null>";
  else
    ss << "\"" << arg << "\"";
}

void PrintArg(int fd, AtFD, rt::Logger &ss, [[maybe_unused]] SyscallCtx &ctx) {
  if (fd == AT_FDCWD)
    ss << "AT_FDCWD";
  else
    ss << fd;
}

template <typename Logger>
bool PrintFlagArr(const std::map<int, std::string> &map, int flags,
                  Logger &ss) {
  bool done_one = false;
  for (int i = 0; i < 32; i++) {
    int flag = 1 << i;
    if (!(flags & flag)) continue;
    if (!done_one)
      done_one = true;
    else
      ss << "|";
    auto it = map.find(flag);
    if (it != map.end()) {
      ss << it->second;
    } else {
      ss << "1 << " << i;
    }
  }
  return done_one;
}

bool PrintArg(const struct pollfd *el, rt::Logger &ss, SyscallCtx &ctx) {
  ss << "{fd=" << el->fd << ", events=";
  PrintFlagArr(poll_flags, el->events, ss);
  ss << ", revents=";
  PrintFlagArr(poll_flags, el->revents, ss);
  ss << "}";
  return true;
}

bool PrintArg(const struct epoll_event *el, rt::Logger &ss, SyscallCtx &ctx) {
  if (!el->events) return false;
  ss << "{events=";
  PrintFlagArr(poll_flags, el->events, ss);
  ss << ", data=" << el->data.u64 << "}";
  return true;
}

void PrintArg(int prot, ProtFlag, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  if (prot == PROT_NONE) {
    ss << "PROT_NONE";
    return;
  }
  PrintFlagArr(protection_flags, prot, ss);
}

void PrintArg(int op, FutexOp, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  int cmd = op & FUTEX_CMD_MASK;
  PrintValMap(futex_flags, cmd, ss);

  if (op & FUTEX_PRIVATE_FLAG) ss << "|FUTEX_PRIVATE";
  if (op & FUTEX_CLOCK_REALTIME) ss << "|FUTEX_CLOCK_REALTIME";

  if (futex_ops_with_val2.count(cmd)) {
    ctx.arg_strs[3].emplace() << (uint32_t)std::get<3>(ctx.args);
  } else if (futex_ops_with_timeout.count(cmd)) {
    const struct timespec *t =
        reinterpret_cast<const struct timespec *>(std::get<3>(ctx.args));
    PrintArg(t, ctx.arg_strs[3].emplace());
  }
}

void PrintArg(int op, SigProcMaskOp, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  PrintValMap(sigprocmask_how, op, ss);
}

void PrintArg(long op, PrctlOp, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  PrintValMap(prctl_ops, op, ss);
}

template <typename Logger>
void PrintOpenFlag(int flags, Logger &ss, bool include_mode = true) {
  bool done_one = PrintFlagArr(open_flags, flags, ss);
  if (include_mode && (flags & (O_WRONLY | O_RDWR)) == 0) {
    if (done_one) ss << "|";
    ss << "O_RDONLY";
  }
}

void PrintArg(int flags, OpenFlag, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  PrintOpenFlag(flags, ss);
}

void PrintArg(unsigned int op, FcntlOp, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  PrintValMap(fcntls, op, ss);
  if (op == F_SETFL) {
    PrintOpenFlag(static_cast<int>(std::get<2>(ctx.args)),
                  ctx.arg_strs[2].emplace(), false);
  } else if (op == F_GETFL && ctx.retval) {
    PrintOpenFlag(static_cast<int>(ctx.retval.value()), ctx.ret_str.emplace());
  }
}

void PrintArg(unsigned int op, IoctlOp, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  if (!PrintValMap(ioctls, op, ss, false)) PrintIoctlReq(op, ss);
  if (op == FIONBIO)
    ctx.arg_strs[2].emplace()
        << "[" << *reinterpret_cast<int *>(std::get<2>(ctx.args)) << "]";
}

void PrintArg(int *fds, FDPair *, rt::Logger &ss,
              [[maybe_unused]] SyscallCtx &ctx) {
  ss << "[" << fds[0] << ", " << fds[1] << "]";
}

void PrintArg(int level, SockoptLevel, rt::Logger &ss, SyscallCtx &ctx) {
  PrintValMap(sockopt_levels, level, ss);
  int sockopt = std::get<2>(ctx.args);

  auto sockopt_handler = [&](const std::map<int, std::string> &val_map,
                             const std::set<int> &intlike_sockopts) {
    auto it = val_map.find(sockopt);
    LOG(ERR) << "Unknown sockopt: " << sockopt;
    if (it == val_map.end()) return;
    ctx.arg_strs[2].emplace(it->second);
    if (intlike_sockopts.count(sockopt)) {
      ctx.arg_strs[3].emplace()
          << "[" << *reinterpret_cast<int *>(std::get<3>(ctx.args)) << "]";
    }
  };
  switch (level) {
    case IPPROTO_IP:
      sockopt_handler(ip_options, ip_int_options);
      break;
    // TODO: add TCP and UDP options
    case SOL_SOCKET:
      sockopt_handler(sock_options, intlike_sockopts);
      if (sockopt == SO_RCVTIMEO || sockopt == SO_SNDTIMEO) {
        struct timeval tv =
            *reinterpret_cast<struct timeval *>(std::get<3>(ctx.args));
        PrintArg(tv, ctx.arg_strs[3].emplace());
      }
      break;
    default:
      break;
  }
}
}  // namespace strace

void LogSignal(const siginfo_t &info) {
  const char *signame;
  if (info.si_signo > 0 && info.si_signo < 32)
    signame = strace::sigmap[info.si_signo - 1];
  else
    signame = "unknown";

  rt::Logger logger(LOG_INFO);
  logger << "[" << myproc().get_pid() << ":" << mythread().get_tid() << "] --- "
         << signame << " {si_signo=" << info.si_signo
         << ", si_code = " << info.si_code;

  if (info.si_signo == SIGCHLD) {
    logger << ", si_pid = " << info.si_pid
           << ", si_status = " << info.si_status;
  } else {
    logger << ", si_addr = " << info.si_addr;
  }

  logger << "} ---";
}
}  // namespace junction
