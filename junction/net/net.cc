extern "C" {
#include <netinet/in.h>
}

#include <cstring>
#include <memory>

#include "junction/base/io.h"
#include "junction/bindings/log.h"
#include "junction/bindings/net.h"
#include "junction/fs/file.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/net/netlink.h"
#include "junction/net/socket.h"
#include "junction/net/tcp_socket.h"
#include "junction/net/udp_socket.h"
#include "junction/net/unix.h"

namespace junction {

namespace {

Status<std::reference_wrapper<Socket>> FDToSocket(int fd) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return MakeError(EBADF);
  if (unlikely(f->get_type() != FileType::kSocket)) return MakeError(ENOTSOCK);
  return std::ref(static_cast<Socket &>(*f));
}

Status<std::shared_ptr<Socket>> CreateSocket(int domain, int type,
                                             int protocol) {
  int flags = type & kFlagNonblock;
  type &= ~(kFlagCloseExec | kFlagNonblock);

  if (unlikely(domain == AF_NETLINK))
    return CreateNetlinkSocket(type, flags, protocol);

  if (domain == AF_UNIX) return CreateUnixSocket(type, protocol, flags);

  if (unlikely(domain != AF_INET)) return MakeError(EAFNOSUPPORT);
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
  Status<std::shared_ptr<Socket>> ret = s.Accept({addr, addrlen}, flags);
  if (unlikely(!ret)) return MakeCError(ret);
  return myproc().get_file_table().Insert(std::move(*ret),
                                          (flags & kFlagCloseExec) > 0);
}

}  // namespace

Status<netaddr> SockAddrPtr::ToNetAddr() const {
  if (unlikely(!addr || Family() != AF_INET || size() < sizeof(sockaddr_in)))
    return MakeError(EINVAL);
  const sockaddr_in *sin = reinterpret_cast<const sockaddr_in *>(addr);
  return netaddr{ntoh32(sin->sin_addr.s_addr), ntoh16(sin->sin_port)};
}

Status<UnixSocketAddr> SockAddrPtr::ToUnixAddr() const {
  if (unlikely(!addr || Family() != AF_UNIX || size() <= sizeof(sa_family_t)))
    return MakeError(EINVAL);
  const sockaddr_un *sun = reinterpret_cast<const sockaddr_un *>(addr);

  UnixSocketAddressType type = UnixSocketAddressType::Pathname;
  size_t max_bytes = sizeof(sun->sun_path);
  max_bytes = std::min(size() - offsetof(sockaddr_un, sun_path), max_bytes);

  const char *fb = sun->sun_path;
  if (*fb == '\0') {
    fb++;
    max_bytes--;
    type = UnixSocketAddressType::Abstract;
  }

  return std::pair{type, std::string(fb, strnlen(fb, max_bytes))};
}

void SockAddrPtr::FromUnixAddr(const UnixSocketAddr &uaddr) {
  sockaddr_un *uin = asPtr<sockaddr_un>();
  uin->sun_family = AF_UNIX;
  const auto &[type, name] = uaddr;

  if (!name.size()) {
    *addrlen = sizeof(uin->sun_family);
    return;
  }

  size_t max_copy = size() - offsetof(sockaddr_un, sun_path);
  char *dst = uin->sun_path;
  if (type == UnixSocketAddressType::Abstract) {
    *dst++ = '\0';
    max_copy--;
  }
  max_copy = std::min(max_copy, name.size() + 1);
  std::memcpy(dst, name.data(), max_copy);
  *addrlen = sizeof(uin->sun_family) + name.size() + 1 + (dst - uin->sun_path);
}

void SockAddrPtr::FromNetAddr(const netaddr &naddr) {
  sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = hton16(naddr.port);
  sin.sin_addr.s_addr = hton32(naddr.ip);
  std::memcpy(Ptr(), &sin, std::min(sizeof(sin), size()));
  *addrlen = sizeof(sockaddr_in);
}

long usys_socket(int domain, int type, int protocol) {
  Status<std::shared_ptr<Socket>> ret = CreateSocket(domain, type, protocol);
  if (unlikely(!ret)) return MakeCError(ret);
  return myproc().get_file_table().Insert(std::move(*ret),
                                          (type & kFlagCloseExec) > 0);
}

long usys_bind(int sockfd, const struct sockaddr *addr_in, socklen_t addrlen) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<void> ret = s.Bind(SockAddrPtr::asConst(addr_in, &addrlen));
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

long usys_connect(int sockfd, const struct sockaddr *addr_in,
                  socklen_t addrlen) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<void> ret = s.Connect(SockAddrPtr::asConst(addr_in, &addrlen));
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

long usys_getsockopt(int sockfd, int level, int option_name, void *option_value,
                     socklen_t *option_len) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  if (level == IPPROTO_IP && option_name == IP_OPTIONS) {
    if (!option_len) return -EINVAL;
    *option_len = 0;
    return 0;
  }
  Socket &s = sock_ret.value().get();
  Status<int> val = s.GetSockOpt(level, option_name);
  if (!val) {
    LOG_ONCE(WARN) << "Unsupported: getsockopt";
  } else {
    if (!option_len || *option_len < sizeof(int)) return -EINVAL;
    *reinterpret_cast<int *>(option_value) = *val;
  }
  return 0;
}

ssize_t usys_recvfrom(int sockfd, void *buf, size_t len, int flags,
                      struct sockaddr *src_addr, socklen_t *addrlen) {
  bool peek = flags & kMsgPeek;
  bool nonblocking = flags & kMsgDontWait;
  flags = flags & ~(kMsgNoSignal | kMsgPeek | kMsgDontWait);
  if (unlikely(flags != 0)) return -EINVAL;
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<size_t> ret = s.ReadFrom(readable_span(static_cast<char *>(buf), len),
                                  {src_addr, addrlen}, peek, nonblocking);
  if (unlikely(!ret)) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_recvmsg(int sockfd, struct msghdr *msg, int flags) {
  bool peek = flags & kMsgPeek;
  bool nonblocking = flags & kMsgDontWait;
  flags = flags & ~(kMsgNoSignal | kMsgPeek | kMsgDontWait);
  if (unlikely(flags != 0)) {
    LOG_ONCE(WARN) << "recvmsg ignoring flags" << flags;
    return -EINVAL;
  }
  if (msg->msg_control || msg->msg_controllen)
    LOG_ONCE(WARN) << "recvmsg: ignoring control message";
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  const SockAddrPtr p = SockAddrPtr::asConst(
      reinterpret_cast<const sockaddr *>(msg->msg_name), &msg->msg_namelen);
  Status<size_t> ret =
      s.ReadvFrom({msg->msg_iov, msg->msg_iovlen}, p, peek, nonblocking);
  if (unlikely(!ret)) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_sendto(int sockfd, const void *buf, size_t len, int flags,
                    const struct sockaddr *dest_addr, socklen_t addrlen) {
  bool nonblocking = flags & kMsgDontWait;
  flags = flags & ~(kMsgNoSignal | kMsgDontWait);
  if (unlikely(flags != 0)) return -EINVAL;
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<ssize_t> ret =
      s.WriteTo(writable_span(static_cast<const char *>(buf), len),
                SockAddrPtr::asConst(dest_addr, &addrlen), nonblocking);
  if (unlikely(!ret)) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  bool nonblocking = flags & kMsgDontWait;
  flags &= ~(kMsgNoSignal | kMsgDontWait);
  if (unlikely(flags != 0)) {
    LOG_ONCE(WARN) << "sendmsg ignoring flags " << flags;
    return -EINVAL;
  }
  if (msg->msg_control || msg->msg_controllen)
    LOG_ONCE(WARN) << "sendmsg: ignoring control message";
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  const SockAddrPtr p = SockAddrPtr::asConst(
      reinterpret_cast<const sockaddr *>(msg->msg_name), &msg->msg_namelen);
  Status<size_t> ret =
      s.WritevTo({msg->msg_iov, msg->msg_iovlen}, p, nonblocking);
  if (unlikely(!ret)) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                      int flags) {
  bool nonblocking = flags & kMsgDontWait;
  flags &= ~(kMsgNoSignal | kMsgDontWait);
  if (unlikely(flags != 0)) {
    LOG_ONCE(WARN) << "sendmsg ignoring flags " << flags;
    return -EINVAL;
  }

  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();

  for (unsigned int i = 0; i < vlen; i++) {
    struct msghdr *msg = &msgvec[i].msg_hdr;
    if (msg->msg_control || msg->msg_controllen)
      LOG_ONCE(WARN) << "sendmsg: ignoring control message";
    const SockAddrPtr p = SockAddrPtr::asConst(
        reinterpret_cast<const sockaddr *>(msg->msg_name), &msg->msg_namelen);
    Status<size_t> ret =
        s.WritevTo({msg->msg_iov, msg->msg_iovlen}, p, nonblocking);
    if (!ret) {
      if (i > 0) return i;
      return MakeCError(ret);
    }
    msgvec[i].msg_len = *ret;
  }

  return vlen;
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
  Status<void> ret = s.RemoteAddr({addr, addrlen});
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

long usys_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<void> ret = s.LocalAddr({addr, addrlen});
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

}  // namespace junction
