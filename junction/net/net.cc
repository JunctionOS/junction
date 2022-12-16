#include "junction/bindings/net.h"

#include <memory>

#include "junction/base/io.h"
#include "junction/bindings/log.h"
#include "junction/kernel/file.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/net/socket.h"
#include "junction/net/socket_placeholder.h"

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

Status<netaddr> ParseSockAddr(const sockaddr *addr, socklen_t addrlen) {
  if (unlikely(!addr || addr->sa_family != AF_INET ||
               addrlen < sizeof(sockaddr_in)))
    return MakeError(EINVAL);

  const sockaddr_in *sin = reinterpret_cast<const sockaddr_in *>(addr);
  return netaddr{ntoh32(sin->sin_addr.s_addr), ntoh16(sin->sin_port)};
}

}  // namespace

// TODO(girfan): Fix the "restrict" keyword for all the net syscalls.
long usys_socket(int domain, int type, int protocol) {
  Status<std::shared_ptr<Socket>> ret =
      SocketPlaceholder::Create(domain, type, protocol);
  if (unlikely(!ret)) return MakeCError(ret);
  return myproc().get_file_table().Insert(std::move(*ret));
}

long usys_bind(int sockfd, const struct sockaddr *addr_in, socklen_t addrlen) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<netaddr> addr = ParseSockAddr(addr_in, addrlen);
  if (!addr) return MakeCError(addr);
  Status<std::shared_ptr<Socket>> ret = s.Bind(*addr);
  if (!ret) return MakeCError(ret);
  myproc().get_file_table().InsertAt(sockfd, std::move(*ret));
  return 0;
}

long usys_connect(int sockfd, const struct sockaddr *addr_in,
                  socklen_t addrlen) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<netaddr> addr = ParseSockAddr(addr_in, addrlen);
  if (!addr) return MakeCError(addr);
  Status<std::shared_ptr<Socket>> ret = s.Connect(*addr);
  if (!ret) return MakeCError(ret);
  myproc().get_file_table().InsertAt(sockfd, std::move(*ret));
  return 0;
}

// TODO(girfan): Think about how to properly handle this.
long usys_setsockopt(int sockfd, [[maybe_unused]] int level,
                     [[maybe_unused]] int option_name,
                     [[maybe_unused]] const void *option_value,
                     [[maybe_unused]] socklen_t option_len) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  LOG(WARN) << "Unsupported: setsockopt";
  return 0;
}

ssize_t usys_recvfrom(int sockfd, void *buf, size_t len, int flags,
                      struct sockaddr *src_addr, socklen_t *addrlen) {
  if (flags != 0 || src_addr != nullptr || addrlen != nullptr) return -EINVAL;
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<size_t> ret =
      s.Read(readable_span(static_cast<char *>(buf), len), &s.get_off_ref());
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_sendto(int sockfd, const void *buf, size_t len, int flags,
                    const struct sockaddr *dest_addr,
                    [[maybe_unused]] socklen_t addrlen) {
  if (flags != 0 || dest_addr != nullptr) return -EINVAL;
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<size_t> ret = s.Write(
      writable_span(static_cast<const char *>(buf), len), &s.get_off_ref());
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

long usys_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<std::shared_ptr<Socket>> ret = s.Accept();
  if (!ret) return MakeCError(ret);
  if (addr) {
    if (!addrlen || *addrlen < sizeof(sockaddr_in)) return -EINVAL;
    Status<netaddr> na = (*ret)->RemoteAddr();
    if (!na) return MakeCError(na);
    sockaddr_in *addr_in = reinterpret_cast<sockaddr_in *>(addr);
    addr_in->sin_family = AF_INET;
    addr_in->sin_port = hton16(na->port);
    addr_in->sin_addr.s_addr = hton32(na->ip);
    *addrlen = sizeof(sockaddr_in);
  }
  return myproc().get_file_table().Insert(std::move(*ret));
}

long usys_shutdown(int sockfd, int how) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<void> ret = s.Shutdown(how);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_listen(int sockfd, int backlog) {
  auto sock_ret = FDToSocket(sockfd);
  if (unlikely(!sock_ret)) return MakeCError(sock_ret);
  Socket &s = sock_ret.value().get();
  Status<void> ret = s.Listen(backlog);
  if (!ret) return MakeCError(ret);
  return 0;
}

}  // namespace junction
