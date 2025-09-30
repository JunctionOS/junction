#include "junction/syscall/strace_maps.h"

extern "C" {
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/ioctl.h>
#include <linux/prctl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
}

#include <map>
#include <set>

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
    VAL(PROT_WRITE),
    VAL(PROT_EXEC),
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
    {O_APPEND, "O_APPEND"},
    {O_ASYNC, "O_ASYNC"},
    {O_CLOEXEC, "O_CLOEXEC"},
    {O_CREAT, "O_CREAT"},
    {O_DIRECT, "O_DIRECT"},
    {O_DIRECTORY, "O_DIRECTORY"},
    {O_DSYNC, "O_DSYNC"},
    {O_EXCL, "O_EXCL"},
    {O_LARGEFILE, "O_LARGEFILE"},
    {O_NOATIME, "O_NOATIME"},
    {O_NOCTTY, "O_NOCTTY"},
    {O_NOFOLLOW, "O_NOFOLLOW"},
    {O_NONBLOCK, "O_NONBLOCK"},
    {O_PATH, "O_PATH"},
    {O_SYNC, "O_SYNC"},
    {O_TRUNC, "O_TRUNC"},
    {O_WRONLY, "O_WRONLY"},
    {O_RDWR, "O_RDWR"},
    {(O_TMPFILE & ~O_DIRECTORY), "O_TMPFILE"}};

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

const std::set<int> futex_ops_with_val2{FUTEX_CMP_REQUEUE, FUTEX_WAKE_OP,
                                        FUTEX_CMP_REQUEUE_PI};

const std::set<int> futex_ops_with_timeout{FUTEX_WAIT, FUTEX_WAIT_BITSET,
                                           FUTEX_LOCK_PI, FUTEX_LOCK_PI2,
                                           FUTEX_WAIT_REQUEUE_PI};

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

const std::map<int, std::string> statx_mask_flags{
    VAL(STATX_TYPE),
    VAL(STATX_MODE),
    VAL(STATX_NLINK),
    VAL(STATX_UID),
    VAL(STATX_GID),
    VAL(STATX_ATIME),
    VAL(STATX_MTIME),
    VAL(STATX_CTIME),
    VAL(STATX_INO),
    VAL(STATX_SIZE),
    VAL(STATX_BLOCKS),
    VAL(STATX_BASIC_STATS),
    // VAL(STATX_ALL), // same as STATX_BASIC_STATS | STATX_BTIME
    VAL(STATX_BTIME),
    VAL(STATX_MNT_ID),
    VAL(STATX_DIOALIGN),
};

const std::map<int, std::string> at_flags{
    VAL(AT_SYMLINK_NOFOLLOW),
    VAL(AT_REMOVEDIR),
    VAL(AT_SYMLINK_FOLLOW),
    VAL(AT_NO_AUTOMOUNT),
    VAL(AT_EMPTY_PATH),
    VAL(AT_STATX_SYNC_TYPE),
    VAL(AT_STATX_SYNC_AS_STAT),
    VAL(AT_STATX_FORCE_SYNC),
    VAL(AT_STATX_DONT_SYNC),
    VAL(AT_RECURSIVE),
    VAL(AT_EACCESS),
};

const std::map<int, std::string> poll_flags{
    VAL(POLLIN),     VAL(POLLPRI),    VAL(POLLOUT),    VAL(POLLRDHUP),
    VAL(POLLERR),    VAL(POLLHUP),    VAL(POLLNVAL),   VAL(POLLRDNORM),
    VAL(POLLRDBAND), VAL(POLLWRNORM), VAL(POLLWRBAND), VAL(POLLMSG)};

const std::map<int, std::string> prctl_ops{
    VAL(PR_CAP_AMBIENT),
    VAL(PR_CAPBSET_READ),
    VAL(PR_CAPBSET_DROP),
    VAL(PR_SET_CHILD_SUBREAPER),
    VAL(PR_GET_CHILD_SUBREAPER),
    VAL(PR_SET_DUMPABLE),
    VAL(PR_GET_DUMPABLE),
    VAL(PR_SET_ENDIAN),
    VAL(PR_GET_ENDIAN),
    VAL(PR_SET_FP_MODE),
    VAL(PR_GET_FP_MODE),
    VAL(PR_SET_FPEMU),
    VAL(PR_GET_FPEMU),
    VAL(PR_SET_FPEXC),
    VAL(PR_GET_FPEXC),
    VAL(PR_SET_IO_FLUSHER),
    VAL(PR_GET_IO_FLUSHER),
    VAL(PR_SET_KEEPCAPS),
    VAL(PR_GET_KEEPCAPS),
    VAL(PR_MCE_KILL),
    VAL(PR_MCE_KILL_GET),
    VAL(PR_SET_MM),
    VAL(PR_SET_VMA),
    VAL(PR_MPX_ENABLE_MANAGEMENT),
    VAL(PR_MPX_DISABLE_MANAGEMENT),
    VAL(PR_SET_NAME),
    VAL(PR_GET_NAME),
    VAL(PR_SET_NO_NEW_PRIVS),
    VAL(PR_GET_NO_NEW_PRIVS),
    VAL(PR_PAC_RESET_KEYS),
    VAL(PR_SET_PDEATHSIG),
    VAL(PR_GET_PDEATHSIG),
    VAL(PR_SET_PTRACER),
    VAL(PR_SET_SECCOMP),
    VAL(PR_GET_SECCOMP),
    VAL(PR_SET_SECUREBITS),
    VAL(PR_GET_SECUREBITS),
    VAL(PR_GET_SPECULATION_CTRL),
    VAL(PR_SET_SPECULATION_CTRL),
    VAL(PR_SVE_SET_VL),
    VAL(PR_SVE_GET_VL),
    VAL(PR_SET_SYSCALL_USER_DISPATCH),
    VAL(PR_SET_TAGGED_ADDR_CTRL),
    VAL(PR_GET_TAGGED_ADDR_CTRL),
    VAL(PR_TASK_PERF_EVENTS_DISABLE),
    VAL(PR_TASK_PERF_EVENTS_ENABLE),
    VAL(PR_SET_THP_DISABLE),
    VAL(PR_GET_THP_DISABLE),
    VAL(PR_GET_TID_ADDRESS),
    VAL(PR_SET_TIMERSLACK),
    VAL(PR_GET_TIMERSLACK),
    VAL(PR_SET_TIMING),
    VAL(PR_GET_TIMING),
    VAL(PR_SET_TSC),
    VAL(PR_GET_TSC),
    VAL(PR_SET_UNALIGN),
    VAL(PR_GET_UNALIGN),
    VAL(PR_GET_AUXV),
    VAL(PR_SET_MDWE),
    VAL(PR_GET_MDWE),
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

const std::map<int, std::string> epoll_ctl_ops{
    VAL(EPOLL_CTL_ADD), VAL(EPOLL_CTL_MOD), VAL(EPOLL_CTL_DEL)};

const char *sigmap[] = {
    "SIGHUP",  "SIGINT",    "SIGQUIT", "SIGILL",    "SIGTRAP", "SIGABRT",
    "SIGBUS",  "SIGFPE",    "SIGKILL", "SIGUSR1",   "SIGSEGV", "SIGUSR2",
    "SIGPIPE", "SIGALRM",   "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT",
    "SIGSTOP", "SIGTSTP",   "SIGTTIN", "SIGTTOU",   "SIGURG",  "SIGXCPU",
    "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH",  "SIGIO",   "SIGPWR",
    "SIGSYS",  "SIGUNUSED"};

const std::map<int, std::string> sigprocmask_how{
    VAL(SIG_BLOCK), VAL(SIG_UNBLOCK), VAL(SIG_SETMASK)};

const std::map<int, std::string> wait_flags = {
    VAL(WEXITED), VAL(WSTOPPED),  VAL(WCONTINUED), VAL(WNOHANG),
    VAL(WNOWAIT), VAL(WUNTRACED), VAL(WCONTINUED),
};

const std::map<int, std::string> sockopt_levels = {
    VAL(SOL_SOCKET),   VAL(IPPROTO_IP),  VAL(IPPROTO_TCP), VAL(IPPROTO_UDP),
    VAL(IPPROTO_IPV6), VAL(IPPROTO_RAW), VAL(SOL_NETLINK),
};

const std::map<int, std::string> sock_options = {
    VAL(SO_DEBUG),
    VAL(SO_REUSEADDR),
    VAL(SO_TYPE),
    VAL(SO_ERROR),
    VAL(SO_DONTROUTE),
    VAL(SO_BROADCAST),
    VAL(SO_SNDBUF),
    VAL(SO_RCVBUF),
    VAL(SO_KEEPALIVE),
    VAL(SO_OOBINLINE),
    VAL(SO_NO_CHECK),
    VAL(SO_PRIORITY),
    VAL(SO_LINGER),
    VAL(SO_BSDCOMPAT),
    VAL(SO_REUSEPORT),
    VAL(SO_PASSCRED),
    VAL(SO_PEERCRED),
    VAL(SO_RCVLOWAT),
    VAL(SO_SNDLOWAT),
    VAL(SO_RCVTIMEO),
    VAL(SO_SNDTIMEO),
    VAL(SO_SECURITY_AUTHENTICATION),
    VAL(SO_SECURITY_ENCRYPTION_TRANSPORT),
    VAL(SO_SECURITY_ENCRYPTION_NETWORK),
    VAL(SO_BINDTODEVICE),
    VAL(SO_DETACH_FILTER),
    VAL(SO_PEERNAME),
    VAL(SO_TIMESTAMP_OLD),
    VAL(SO_ACCEPTCONN),
    VAL(SO_PEERSEC),
    VAL(SO_SNDBUFFORCE),
    VAL(SO_RCVBUFFORCE),
    VAL(SO_PASSSEC),
    VAL(SO_TIMESTAMPNS_OLD),
    VAL(SO_MARK),
    VAL(SO_TIMESTAMPING_OLD),
    VAL(SO_PROTOCOL),
    VAL(SO_DOMAIN),
    VAL(SO_RXQ_OVFL),
    VAL(SO_WIFI_STATUS),
    VAL(SO_PEEK_OFF),
    VAL(SO_NOFCS),
    VAL(SO_LOCK_FILTER),
    VAL(SO_SELECT_ERR_QUEUE),
    VAL(SO_BUSY_POLL),
    VAL(SO_MAX_PACING_RATE),
    VAL(SO_BPF_EXTENSIONS),
    VAL(SO_INCOMING_CPU),
    VAL(SO_ATTACH_BPF),
    VAL(SO_ATTACH_REUSEPORT_CBPF),
    VAL(SO_ATTACH_REUSEPORT_EBPF),
    VAL(SO_CNX_ADVICE),
    VAL(SO_MEMINFO),
    VAL(SO_INCOMING_NAPI_ID),
    VAL(SO_COOKIE),
    VAL(SO_PEERGROUPS),
    VAL(SO_ZEROCOPY),
    VAL(SO_TXTIME),
    VAL(SO_BINDTOIFINDEX),
    VAL(SO_TIMESTAMP_NEW),
    VAL(SO_TIMESTAMPNS_NEW),
    VAL(SO_TIMESTAMPING_NEW),
    VAL(SO_RCVTIMEO_NEW),
    VAL(SO_SNDTIMEO_NEW),
    VAL(SO_DETACH_REUSEPORT_BPF),
    VAL(SO_PREFER_BUSY_POLL),
    VAL(SO_BUSY_POLL_BUDGET),
    VAL(SO_NETNS_COOKIE),
    VAL(SO_BUF_LOCK),
    VAL(SO_RESERVE_MEM),
    VAL(SO_TXREHASH),
    VAL(SO_RCVMARK),
    VAL(SO_PASSPIDFD),
    VAL(SO_PEERPIDFD),
    // VAL(SO_RCVPRIORITY),
    // VAL(SO_PASSRIGHTS),
    // VAL(SO_INQ),
};

const std::set<int> intlike_sockopts = {
    SO_DEBUG,
    SO_REUSEADDR,
    SO_DONTROUTE,
    SO_BROADCAST,
    SO_SNDBUF,
    SO_RCVBUF,
    SO_KEEPALIVE,
    SO_OOBINLINE,
    SO_NO_CHECK,
    SO_PRIORITY,
    SO_BSDCOMPAT,
    SO_REUSEPORT,
    SO_PASSCRED,
    SO_RCVLOWAT,
    SO_SNDLOWAT,
    SO_DETACH_FILTER,
    SO_TIMESTAMP_OLD,
    SO_ACCEPTCONN,
    SO_SNDBUFFORCE,
    SO_RCVBUFFORCE,
    SO_PASSSEC,
    SO_TIMESTAMPNS_OLD,
    SO_MARK,
    SO_TIMESTAMPING_OLD,
    SO_RXQ_OVFL,
    SO_WIFI_STATUS,
    SO_PEEK_OFF,
    SO_NOFCS,
    SO_LOCK_FILTER,
    SO_SELECT_ERR_QUEUE,
    SO_BUSY_POLL,
    SO_INCOMING_CPU,
    SO_CNX_ADVICE,
    SO_INCOMING_NAPI_ID,
    SO_ZEROCOPY,
    SO_TIMESTAMP_NEW,
    SO_TIMESTAMPNS_NEW,
    SO_TIMESTAMPING_NEW,
    SO_DETACH_REUSEPORT_BPF,
    SO_PREFER_BUSY_POLL,
    SO_BUSY_POLL_BUDGET,
    SO_RESERVE_MEM,
    SO_RCVMARK,
    SO_PASSPIDFD,
    // SO_RCVPRIORITY,
    // SO_PASSRIGHTS,
    // SO_INQ
};

const std::map<int, std::string> ip_options = {VAL(IP_ADD_MEMBERSHIP),
                                               VAL(IP_ADD_SOURCE_MEMBERSHIP),
                                               VAL(IP_BIND_ADDRESS_NO_PORT),
                                               VAL(IP_BLOCK_SOURCE),
                                               VAL(IP_DROP_MEMBERSHIP),
                                               VAL(IP_DROP_SOURCE_MEMBERSHIP),
                                               VAL(IP_FREEBIND),
                                               VAL(IP_HDRINCL),
                                               VAL(IP_LOCAL_PORT_RANGE),
                                               VAL(IP_MSFILTER),
                                               VAL(IP_MTU),
                                               VAL(IP_MTU_DISCOVER),
                                               VAL(IP_MULTICAST_ALL),
                                               VAL(IP_MULTICAST_IF),
                                               VAL(IP_MULTICAST_LOOP),
                                               VAL(IP_MULTICAST_TTL),
                                               VAL(IP_NODEFRAG),
                                               VAL(IP_OPTIONS),
                                               VAL(IP_PASSSEC),
                                               VAL(IP_PKTINFO),
                                               VAL(IP_RECVERR),
                                               VAL(IP_RECVOPTS),
                                               VAL(IP_RECVORIGDSTADDR),
                                               VAL(IP_RECVTOS),
                                               VAL(IP_RECVTTL),
                                               VAL(IP_RETOPTS),
                                               VAL(IP_ROUTER_ALERT),
                                               VAL(IP_TOS),
                                               VAL(IP_TRANSPARENT),
                                               VAL(IP_TTL),
                                               VAL(IP_UNBLOCK_SOURCE)};

// Options that take an integer pointer as optval
const std::set<int> ip_int_options = {IP_FREEBIND,
                                      IP_HDRINCL,
                                      IP_LOCAL_PORT_RANGE,
                                      IP_MTU,
                                      IP_MTU_DISCOVER,
                                      IP_MULTICAST_ALL,
                                      IP_MULTICAST_LOOP,
                                      IP_MULTICAST_TTL,
                                      IP_NODEFRAG,
                                      IP_PASSSEC,
                                      IP_PKTINFO,
                                      IP_RECVERR,
                                      IP_RECVOPTS,
                                      IP_RECVORIGDSTADDR,
                                      IP_RECVTOS,
                                      IP_RECVTTL,
                                      IP_RETOPTS,
                                      IP_ROUTER_ALERT,
                                      IP_TOS,
                                      IP_TRANSPARENT,
                                      IP_TTL};

}  // namespace strace
}  // namespace junction
