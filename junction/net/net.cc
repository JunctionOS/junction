extern "C" {
#include <netinet/in.h>
}

#include <cstring>
#include <memory>

#include "junction/base/io.h"
#include "junction/bindings/log.h"
#include "junction/bindings/net.h"
#include "junction/kernel/file.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/net/socket.h"
#include "junction/net/tcp_socket.h"
#include "junction/net/udp_socket.h"

namespace junction {

namespace {

// Define inet address struct to avoid pulling in system headers.
struct sockaddr_in {
  short sin_family;
  unsigned short sin_port;
  struct {
    unsigned int s_addr;
  } sin_addr;
  char sin_zero[8];
};

Status<std::reference_wrapper<Socket>> FDToSocket(int fd) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return MakeError(EBADF);
  if (unlikely(f->get_type() != FileType::kSocket)) return MakeError(ENOTSOCK);
  return std::ref(static_cast<Socket &>(*f));
}

Status<netaddr> SockAddrToNetAddr(const sockaddr *addr, socklen_t addrlen) {
  if (unlikely(!addr || addr->sa_family != AF_INET ||
               addrlen < sizeof(sockaddr_in))) {
    return MakeError(EINVAL);
  }
  const sockaddr_in *sin = reinterpret_cast<const sockaddr_in *>(addr);
  return netaddr{ntoh32(sin->sin_addr.s_addr), ntoh16(sin->sin_port)};
}

Status<void> NetAddrToSockAddr(const netaddr &naddr, sockaddr *saddr,
                               socklen_t *addrlen) {
  if (unlikely(!saddr || !addrlen)) return MakeError(EINVAL);

  sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = hton16(naddr.port);
  sin.sin_addr.s_addr = hton32(naddr.ip);
  std::memcpy(saddr, &sin,
              std::min(sizeof(sin), static_cast<size_t>(*addrlen)));
  *addrlen = sizeof(sockaddr_in);
  return {};
}

Status<std::shared_ptr<Socket>> CreateSocket(int domain, int type) {
  if (unlikely(domain != AF_INET)) return MakeError(EINVAL);
  int flags = type & kFlagNonblock;
  type &= ~(kFlagCloseExec | kFlagNonblock);
  if (type == SOCK_STREAM)
    return std::make_shared<TCPSocket>(flags);
  else if (type == SOCK_DGRAM)
    return std::make_shared<UDPSocket>(flags);
  else
    return MakeError(EINVAL);
}

long DoAccept(int sockfd, sockaddr *addr, socklen_t *addrlen, int flags = 0) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<std::shared_ptr<Socket>> ret = s.Accept(flags);
  if (unlikely(!ret)) return MakeCError(ret);
  if (addr) {
    Status<netaddr> na = (*ret)->RemoteAddr();
    if (!na) return MakeCError(na);
    auto conv_ret = NetAddrToSockAddr(*na, addr, addrlen);
    if (unlikely(!conv_ret)) return MakeCError(conv_ret);
  }
  return myproc().get_file_table().Insert(std::move(*ret),
                                          (flags & kFlagCloseExec) > 0);
}

}  // namespace

long usys_socket(int domain, int type, [[maybe_unused]] int protocol) {
  Status<std::shared_ptr<Socket>> ret = CreateSocket(domain, type);
  if (unlikely(!ret)) return MakeCError(ret);
  return myproc().get_file_table().Insert(std::move(*ret),
                                          (type & kFlagCloseExec) > 0);
}

long usys_bind(int sockfd, const struct sockaddr *addr_in, socklen_t addrlen) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<netaddr> addr = SockAddrToNetAddr(addr_in, addrlen);
  if (unlikely(!addr)) return MakeCError(addr);
  Status<void> ret = s.Bind(*addr);
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

long usys_connect(int sockfd, const struct sockaddr *addr_in,
                  socklen_t addrlen) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<netaddr> addr = SockAddrToNetAddr(addr_in, addrlen);
  if (unlikely(!addr)) return MakeCError(addr);
  Status<void> ret = s.Connect(*addr);
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

// TODO(girfan): Think about how to properly handle this.
long usys_setsockopt(int sockfd, [[maybe_unused]] int level,
                     [[maybe_unused]] int option_name,
                     [[maybe_unused]] const void *option_value,
                     [[maybe_unused]] socklen_t option_len) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  if (level == SOL_IPV6) {
    return -ENOPROTOOPT;
  }
  LOG_ONCE(WARN) << "Unsupported: setsockopt";
  return 0;
}

long usys_getsockopt(int sockfd, [[maybe_unused]] int level,
                     [[maybe_unused]] int option_name,
                     [[maybe_unused]] void *option_value,
                     [[maybe_unused]] socklen_t *option_len) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  LOG_ONCE(WARN) << "Unsupported: getsockopt";
  return 0;
}

ssize_t usys_recvfrom(int sockfd, void *buf, size_t len, int flags,
                      struct sockaddr *src_addr, socklen_t *addrlen) {
  flags = flags & ~kMsgNoSignal;
  if (unlikely(flags != 0)) return -EINVAL;
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  netaddr addr;
  Status<size_t> ret = s.ReadFrom(readable_span(static_cast<char *>(buf), len),
                                  src_addr ? &addr : nullptr);
  if (unlikely(!ret)) return MakeCError(ret);
  if (src_addr) {
    auto conv_ret = NetAddrToSockAddr(addr, src_addr, addrlen);
    if (unlikely(!conv_ret)) return MakeCError(conv_ret);
  }
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_sendto(int sockfd, const void *buf, size_t len, int flags,
                    const struct sockaddr *dest_addr, socklen_t addrlen) {
  flags = flags & ~kMsgNoSignal;
  if (unlikely(flags != 0)) return -EINVAL;
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  netaddr addr;
  if (dest_addr) {
    Status<netaddr> naddr = SockAddrToNetAddr(dest_addr, addrlen);
    if (unlikely(!naddr)) return MakeCError(naddr);
    addr = *naddr;
  }

  Status<size_t> ret =
      s.WriteTo(writable_span(static_cast<const char *>(buf), len),
                dest_addr ? &addr : nullptr);
  if (unlikely(!ret)) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  if (flags) LOG_ONCE(WARN) << "sendmsg ignoring flags " << flags;
  if (msg->msg_control || msg->msg_controllen)
    LOG_ONCE(WARN) << "sendmsg: ignoring control message";
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();

  netaddr addr;
  if (msg->msg_name) {
    Status<netaddr> naddr = SockAddrToNetAddr(
        reinterpret_cast<const sockaddr *>(msg->msg_name), msg->msg_namelen);
    if (unlikely(!naddr)) return MakeCError(naddr);
    addr = *naddr;
  }

  Status<size_t> ret = s.WritevTo({msg->msg_iov, msg->msg_iovlen},
                                  msg->msg_name ? &addr : nullptr);
  if (unlikely(!ret)) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

long usys_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  return DoAccept(sockfd, addr, addrlen);
}

long usys_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
                  int flags) {
  if ((flags & ~(kFlagNonblock | kFlagCloseExec)) != 0) return -EINVAL;
  return DoAccept(sockfd, addr, addrlen, flags & kFlagNonblock);
}

long usys_shutdown(int sockfd, int how) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<void> ret = s.Shutdown(how);
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

long usys_listen(int sockfd, int backlog) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<void> ret = s.Listen(backlog);
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

long usys_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<netaddr> ret = s.RemoteAddr();
  if (unlikely(!ret)) return MakeCError(ret);
  auto conv_ret = NetAddrToSockAddr(*ret, addr, addrlen);
  if (unlikely(!conv_ret)) return MakeCError(conv_ret);
  return 0;
}

long usys_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<netaddr> ret = s.LocalAddr();
  if (unlikely(!ret)) return MakeCError(ret);
  auto conv_ret = NetAddrToSockAddr(*ret, addr, addrlen);
  if (unlikely(!conv_ret)) return MakeCError(conv_ret);
  return 0;
}

}  // namespace junction
