#include "junction/syscall/strace.h"

extern "C" {
#include <linux/futex.h>
#include <linux/ioctl.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
}

#include <map>

#include "junction/bindings/log.h"

#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25 /* Synchronous hugepage collapse */
#endif

#ifndef CLONE_CLEAR_SIGHAND
#define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

namespace junction {

namespace strace {

#define VAL(x) \
  { x, #x }

const std::map<int, std::string> protection_flags{
    VAL(PROT_READ),
    {PROT_WRITE, "PROT_WRITE"},
    {PROT_EXEC, "PROT_EXEC"},
};

const std::map<int, std::string> mmap_flags{
    {MAP_SHARED, "MAP_SHARED"},
    {MAP_PRIVATE, "MAP_PRIVATE"},
    {MAP_ANONYMOUS, "MAP_ANONYMOUS"},
    {MAP_FIXED, "MAP_FIXED"},
    {MAP_FIXED_NOREPLACE, "MAP_FIXED_NOREPLACE"},
    {MAP_GROWSDOWN, "MAP_GROWSDOWN"},
    {MAP_HUGETLB, "MAP_HUGETLB"},
    {MAP_LOCKED, "MAP_LOCKED"},
    {MAP_NONBLOCK, "MAP_NONBLOCK"},
    {MAP_NORESERVE, "MAP_NORESERVE"},
    {MAP_POPULATE, "MAP_POPULATE"},
    {MAP_STACK, "MAP_STACK"},
};

const std::map<int, std::string> open_flags{
    {O_APPEND, "O_APPEND"},       {O_ASYNC, "O_ASYNC"},
    {O_CLOEXEC, "O_CLOEXEC"},     {O_CREAT, "O_CREAT"},
    {O_DIRECT, "O_DIRECT"},       {O_DIRECTORY, "O_DIRECTORY"},
    {O_DSYNC, "O_DSYNC"},         {O_EXCL, "O_EXCL"},
    {O_LARGEFILE, "O_LARGEFILE"}, {O_NOATIME, "O_NOATIME"},
    {O_NOCTTY, "O_NOCTTY"},       {O_NOFOLLOW, "O_NOFOLLOW"},
    {O_NONBLOCK, "O_NONBLOCK"},   {O_PATH, "O_PATH"},
    {O_SYNC, "O_SYNC"},           {O_TMPFILE, "O_TMPFILE"},
    {O_TRUNC, "O_TRUNC"},         {O_WRONLY, "O_WRONLY"},
    {O_RDWR, "O_RDWR"},
};

const std::map<int, std::string> madvise_hints{
    {MADV_NORMAL, "MADV_NORMAL"},
    {MADV_DONTNEED, "MADV_DONTNEED"},
    {MADV_RANDOM, "MADV_RANDOM"},
    {MADV_REMOVE, "MADV_REMOVE"},
    {MADV_SEQUENTIAL, "MADV_SEQUENTIAL"},
    {MADV_DONTFORK, "MADV_DONTFORK"},
    {MADV_WILLNEED, "MADV_WILLNEED"},
    {MADV_DOFORK, "MADV_DOFORK"},
    {MADV_HUGEPAGE, "MADV_HUGEPAGE"},
    {MADV_HWPOISON, "MADV_HWPOISON"},
    {MADV_NOHUGEPAGE, "MADV_NOHUGEPAGE"},
    {MADV_MERGEABLE, "MADV_MERGEABLE"},
    {MADV_COLLAPSE, "MADV_COLLAPSE"},
    {MADV_UNMERGEABLE, "MADV_UNMERGEABLE"},
    {MADV_DONTDUMP, "MADV_DONTDUMP"},
    {MADV_DODUMP, "MADV_DODUMP"},
    {MADV_FREE, "MADV_FREE"},
    {MADV_WIPEONFORK, "MADV_WIPEONFORK"},
    {MADV_COLD, "MADV_COLD"},
    {MADV_PAGEOUT, "MADV_PAGEOUT"},
    {MADV_POPULATE_READ, "MADV_POPULATE_READ"},
    {MADV_POPULATE_WRITE, "MADV_POPULATE_WRITE"},
};

const std::map<int, std::string> clone_flags{
    {CLONE_CHILD_CLEARTID, "CLONE_CHILD_CLEARTID"},
    {CLONE_CHILD_SETTID, "CLONE_CHILD_SETTID"},
    {CLONE_CLEAR_SIGHAND, "CLONE_CLEAR_SIGHAND"},
    {CLONE_DETACHED, "CLONE_DETACHED"},
    {CLONE_FILES, "CLONE_FILES"},
    {CLONE_FS, "CLONE_FS"},
    {CLONE_INTO_CGROUP, "CLONE_INTO_CGROUP"},
    {CLONE_IO, "CLONE_IO"},
    {CLONE_NEWCGROUP, "CLONE_NEWCGROUP"},
    {CLONE_NEWIPC, "CLONE_NEWIPC"},
    {CLONE_NEWNET, "CLONE_NEWNET"},
    {CLONE_NEWNS, "CLONE_NEWNS"},
    {CLONE_NEWPID, "CLONE_NEWPID"},
    {CLONE_NEWUSER, "CLONE_NEWUSER"},
    {CLONE_NEWUTS, "CLONE_NEWUTS"},
    {CLONE_PARENT, "CLONE_PARENT"},
    {CLONE_PARENT_SETTID, "CLONE_PARENT_SETTID"},
    {CLONE_PIDFD, "CLONE_PIDFD"},
    {CLONE_PTRACE, "CLONE_PTRACE"},
    {CLONE_SETTLS, "CLONE_SETTLS"},
    {CLONE_SIGHAND, "CLONE_SIGHAND"},
    {CLONE_SYSVSEM, "CLONE_SYSVSEM"},
    {CLONE_THREAD, "CLONE_THREAD"},
    {CLONE_UNTRACED, "CLONE_UNTRACED"},
    {CLONE_VFORK, "CLONE_VFORK"},
    {CLONE_VM, "CLONE_VM"},
};

const std::map<int, std::string> futex_flags{
    {FUTEX_WAKE_BITSET, "FUTEX_WAKE_BITSET"},
    {FUTEX_WAIT, "FUTEX_WAIT"},
    {FUTEX_WAKE, "FUTEX_WAKE"},
    {FUTEX_FD, "FUTEX_FD"},
    {FUTEX_REQUEUE, "FUTEX_REQUEUE"},
    {FUTEX_CMP_REQUEUE, "FUTEX_CMP_REQUEUE"},
    {FUTEX_WAKE_OP, "FUTEX_WAKE_OP"},
    {FUTEX_WAIT_BITSET, "FUTEX_WAIT_BITSET"},
    {FUTEX_LOCK_PI, "FUTEX_LOCK_PI"},
    {FUTEX_LOCK_PI2, "FUTEX_LOCK_PI2"},
    {FUTEX_TRYLOCK_PI, "FUTEX_TRYLOCK_PI"},
    {FUTEX_UNLOCK_PI, "FUTEX_UNLOCK_PI"},
    {FUTEX_CMP_REQUEUE_PI, "FUTEX_CMP_REQUEUE_PI"},
    {FUTEX_WAIT_REQUEUE_PI, "FUTEX_WAIT_REQUEUE_PI"},
};

const std::map<int, std::string> ioctls{
    VAL(TCGETS), VAL(TCSETS), VAL(TCSETSW), VAL(TCSETSF), VAL(TCGETA),
    VAL(TCSETA), VAL(TCSETAW), VAL(TCSETAF), VAL(TCSBRK), VAL(TCXONC),
    VAL(TCFLSH), VAL(TIOCEXCL), VAL(TIOCNXCL), VAL(TIOCSCTTY), VAL(TIOCGPGRP),
    VAL(TIOCSPGRP), VAL(TIOCOUTQ), VAL(TIOCSTI), VAL(TIOCGWINSZ),
    VAL(TIOCSWINSZ), VAL(TIOCMGET), VAL(TIOCMBIS), VAL(TIOCMBIC), VAL(TIOCMSET),
    VAL(TIOCGSOFTCAR), VAL(TIOCSSOFTCAR), VAL(FIONREAD), VAL(TIOCINQ),
    VAL(TIOCLINUX), VAL(TIOCCONS), VAL(TIOCGSERIAL), VAL(TIOCSSERIAL),
    VAL(TIOCPKT), VAL(FIONBIO), VAL(TIOCNOTTY), VAL(TIOCSETD), VAL(TIOCGETD),
    VAL(TCSBRKP), VAL(TIOCSBRK), VAL(TIOCCBRK), VAL(TIOCGSID),
    // VAL(TCGETS2), VAL(TCSETS2), VAL(TCSETSW2), VAL(TCSETSF2),
    VAL(TIOCGRS485), VAL(TIOCSRS485), VAL(TIOCGPTN), VAL(TIOCSPTLCK),
    VAL(TCGETX), VAL(TCSETX), VAL(TCSETXF), VAL(TCSETXW), VAL(FIONCLEX),
    VAL(FIOCLEX), VAL(FIOASYNC), VAL(TIOCSERCONFIG), VAL(TIOCSERGWILD),
    VAL(TIOCSERSWILD), VAL(TIOCGLCKTRMIOS), VAL(TIOCSLCKTRMIOS),
    VAL(TIOCSERGSTRUCT), VAL(TIOCSERGETLSR), VAL(TIOCSERGETMULTI),
    VAL(TIOCSERSETMULTI), VAL(TIOCMIWAIT), VAL(TIOCGICOUNT),
    // VAL(TIOCGHAYESESP), VAL(TIOCSHAYESESP),
    VAL(TIOCPKT_DATA), VAL(TIOCPKT_FLUSHREAD), VAL(TIOCPKT_FLUSHWRITE),
    VAL(TIOCPKT_STOP), VAL(TIOCPKT_START), VAL(TIOCPKT_NOSTOP),
    VAL(TIOCPKT_DOSTOP), VAL(TIOCSER_TEMT), VAL(TIOCGPTPEER)};

const std::map<int, std::string> fcntls{
    VAL(F_DUPFD),
    VAL(F_DUPFD_CLOEXEC),
    VAL(F_GETFD),
    VAL(F_SETFD),
    VAL(F_GETFL),
    VAL(F_SETFL),
    VAL(F_SETLK),
    VAL(F_SETLKW),
    VAL(F_GETLK),
    VAL(F_OFD_SETLK),
    VAL(F_OFD_SETLKW),
    VAL(F_OFD_GETLK),
    VAL(F_GETOWN),
    VAL(F_SETOWN),
    VAL(F_GETOWN_EX),
    VAL(F_SETOWN_EX),
    VAL(F_GETSIG),
    VAL(F_SETSIG),
    VAL(F_SETLEASE),
    VAL(F_GETLEASE),
    VAL(F_NOTIFY),
    VAL(F_SETPIPE_SZ),
    VAL(F_GETPIPE_SZ),
    VAL(F_ADD_SEALS),
    VAL(F_GET_SEALS),
    VAL(F_GET_RW_HINT),
    VAL(F_SET_RW_HINT),
    VAL(F_GET_FILE_RW_HINT),
    VAL(F_SET_FILE_RW_HINT),
};

const std::map<int, std::string> sock_domains{
    VAL(AF_UNIX),   VAL(AF_LOCAL),     VAL(AF_INET),    VAL(AF_AX25),
    VAL(AF_IPX),    VAL(AF_APPLETALK), VAL(AF_X25),     VAL(AF_INET6),
    VAL(AF_DECnet), VAL(AF_KEY),       VAL(AF_NETLINK), VAL(AF_PACKET),
    VAL(AF_RDS),    VAL(AF_PPPOX),     VAL(AF_LLC),     VAL(AF_IB),
    VAL(AF_MPLS),   VAL(AF_CAN),       VAL(AF_TIPC),    VAL(AF_BLUETOOTH),
    VAL(AF_ALG),    VAL(AF_VSOCK),     VAL(AF_KCM),     VAL(AF_XDP),
};

const std::map<int, std::string> sock_types{
    VAL(SOCK_STREAM), VAL(SOCK_DGRAM), VAL(SOCK_SEQPACKET),
    VAL(SOCK_RAW),    VAL(SOCK_RDM),   VAL(SOCK_PACKET),
};

const std::map<int, std::string> msg_flags{
    VAL(MSG_CMSG_CLOEXEC), VAL(MSG_DONTWAIT), VAL(MSG_ERRQUEUE),
    VAL(MSG_OOB),          VAL(MSG_PEEK),     VAL(MSG_TRUNC),
    VAL(MSG_WAITALL),      VAL(MSG_CONFIRM),  VAL(MSG_DONTROUTE),
    VAL(MSG_EOR),          VAL(MSG_MORE),     VAL(MSG_NOSIGNAL),
    VAL(MSG_OOB),
};

const char *sigmap[] = {
    "SIGHUP",  "SIGINT",    "SIGQUIT", "SIGILL",    "SIGTRAP", "SIGABRT",
    "SIGBUS",  "SIGFPE",    "SIGKILL", "SIGUSR1",   "SIGSEGV", "SIGUSR2",
    "SIGPIPE", "SIGALRM",   "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT",
    "SIGSTOP", "SIGTSTP",   "SIGTTIN", "SIGTTOU",   "SIGURG",  "SIGXCPU",
    "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH",  "SIGIO",   "SIGPWR",
    "SIGSYS",  "SIGUNUSED"};

void PrintValMap(const std::map<int, std::string> &map, int val,
                 rt::Logger &ss) {
  auto it = map.find(val);
  if (it != map.end())
    ss << it->second;
  else
    ss << val;
}

void PrintArg(int op, SocketDomain, rt::Logger &ss) {
  PrintValMap(sock_domains, op, ss);
}

void PrintArg(int op, SocketType, rt::Logger &ss) {
  int type = op & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
  PrintValMap(sock_types, type, ss);
  if (op & SOCK_NONBLOCK) ss << "|SOCK_NONBLOCK";
  if (op & SOCK_CLOEXEC) ss << "|SOCK_CLOEXEC";
}

void PrintArg(int advice, MAdviseHint, rt::Logger &ss) {
  PrintValMap(madvise_hints, advice, ss);
}

void PrintArg(int signo, SignalNumber, rt::Logger &ss) {
  ss << sigmap[signo - 1];
}

void PrintArg(const char *arg, PathName *, rt::Logger &ss) {
  ss << "\"" << arg << "\"";
}

void PrintArg(int fd, AtFD, rt::Logger &ss) {
  if (fd == AT_FDCWD)
    ss << "AT_FDCWD";
  else
    ss << fd;
}

bool PrintFlagArr(const std::map<int, std::string> &map, int flags,
                  rt::Logger &ss) {
  bool done_one = false;
  for (const auto &[flag, name] : map) {
    if (!(flags & flag)) continue;
    if (!done_one)
      done_one = true;
    else
      ss << "|";
    ss << name;
  }
  return done_one;
}

void PrintArg(int op, MessageFlag, rt::Logger &ss) {
  PrintFlagArr(msg_flags, op, ss);
}

void PrintArg(int prot, ProtFlag, rt::Logger &ss) {
  if (prot == PROT_NONE) {
    ss << "PROT_NONE";
    return;
  }
  PrintFlagArr(protection_flags, prot, ss);
}

void PrintArg(int op, FutexOp, rt::Logger &ss) {
  int cmd = op & FUTEX_CMD_MASK;
  PrintValMap(futex_flags, cmd, ss);

  if (op & FUTEX_PRIVATE_FLAG) ss << "|FUTEX_PRIVATE_FLAG";
  if (op & FUTEX_CLOCK_REALTIME) ss << "|FUTEX_CLOCK_REALTIME";
}

void PrintArg(unsigned int op, FcntlOp, rt::Logger &ss) {
  PrintValMap(fcntls, op, ss);
}

void PrintArg(unsigned int op, IoctlOp, rt::Logger &ss) {
  PrintValMap(ioctls, op, ss);
}

void PrintArg(int flags, MMapFlag, rt::Logger &ss) {
  PrintFlagArr(mmap_flags, flags, ss);
}

void PrintArg(unsigned long flags, CloneFlag, rt::Logger &ss) {
  PrintFlagArr(clone_flags, flags, ss);
}

void PrintArg(int flags, OpenFlag, rt::Logger &ss) {
  bool done_one = PrintFlagArr(open_flags, flags, ss);
  if ((flags & (O_WRONLY | O_RDWR)) == 0) {
    if (done_one) ss << "|";
    ss << "O_RDONLY";
  }
}

void PrintArg(int *fds, FDPair *, rt::Logger &ss) {
  ss << "[" << fds[0] << ", " << fds[1] << "]";
}

}  // namespace strace

void LogSignal(const siginfo_t &info) {
  const char *signame;
  if (info.si_signo > 0 && info.si_signo < 32)
    signame = strace::sigmap[info.si_signo - 1];
  else
    signame = "unknown";

  LOG(INFO) << "[" << myproc().get_pid() << ":" << mythread().get_tid()
            << "] --- " << signame << " {si_signo=" << info.si_signo
            << ", si_code = " << info.si_code << ", si_addr = " << info.si_addr
            << "} ---";
}
}  // namespace junction
