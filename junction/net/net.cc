#include "junction/bindings/net.h"

#include <memory>

#include "junction/base/io.h"
#include "junction/bindings/log.h"
#include "junction/kernel/file.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/net/socket.h"
#include "junction/net/socket_placeholder.h"

// Define inet address struct to avoid pulling in system headers.
struct sockaddr_in {
  short sin_family;
  unsigned short sin_port;
  struct {
    unsigned int s_addr;
  } sin_addr;
  char sin_zero[8];
};

namespace junction {

Status<netaddr> ParseSockAddr(const sockaddr *addr, socklen_t addrlen) {
  if (unlikely(!addr || addr->sa_family != AF_INET ||
               addrlen < sizeof(sockaddr_in)))
    return MakeError(EINVAL);

  const sockaddr_in *sin = reinterpret_cast<const sockaddr_in *>(addr);
  return netaddr{ntoh32(sin->sin_addr.s_addr), ntoh16(sin->sin_port)};
}

// TODO(girfan): Fix the "restrict" keyword for all the net syscalls.
long usys_socket(int domain, int type, int protocol) {
  Status<std::shared_ptr<Socket>> ret =
      SocketPlaceholder::Create(domain, type, protocol);
  if (unlikely(!ret)) return -ret.error().code();
  FileTable &ftbl = myproc().get_file_table();
  return ftbl.Insert(std::move(*ret));
}

long usys_bind(int sockfd, const struct sockaddr *addr_in, socklen_t addrlen) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(sockfd);
  if (unlikely(!f)) return -EBADF;
  if (unlikely(f->get_type() != FileType::kSocket)) return -ENOTSOCK;
  Socket *s = static_cast<Socket *>(f);
  Status<netaddr> addr = ParseSockAddr(addr_in, addrlen);
  if (!addr) return -addr.error().code();
  Status<std::shared_ptr<Socket>> ret = s->Bind(*addr);
  if (!ret) return -ret.error().code();
  ftbl.InsertAt(sockfd, std::move(*ret));
  return 0;
}

long usys_connect(int sockfd, const struct sockaddr *addr_in,
                  socklen_t addrlen) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(sockfd);
  if (unlikely(!f)) return -EBADF;
  if (unlikely(f->get_type() != FileType::kSocket)) return -ENOTSOCK;
  Socket *s = static_cast<Socket *>(f);
  Status<netaddr> addr = ParseSockAddr(addr_in, addrlen);
  if (!addr) return -addr.error().code();
  Status<std::shared_ptr<Socket>> ret = s->Connect(*addr);
  if (!ret) return -ret.error().code();
  ftbl.InsertAt(sockfd, std::move(*ret));
  return 0;
}

// TODO(girfan): Think about how to properly handle this.
long usys_setsockopt(int socket, [[maybe_unused]] int level,
                     [[maybe_unused]] int option_name,
                     [[maybe_unused]] const void *option_value,
                     [[maybe_unused]] socklen_t option_len) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(socket);
  if (unlikely(!f)) return -EBADF;
  if (unlikely(f->get_type() != FileType::kSocket)) return -ENOTSOCK;
  LOG(WARN) << "Unsupported: setsockopt";
  return 0;
}

ssize_t usys_recvfrom(int sockfd, void *buf, size_t len, int flags,
                      struct sockaddr *src_addr, socklen_t *addrlen) {
  if (flags != 0 || src_addr != nullptr || addrlen != nullptr) return -EINVAL;
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(sockfd);
  if (unlikely(!f)) return -EBADF;
  if (unlikely(f->get_type() != FileType::kSocket)) return -ENOTSOCK;
  Status<size_t> ret =
      f->Read(readable_span(static_cast<char *>(buf), len), &f->get_off_ref());
  if (!ret) return -ret.error().code();
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_sendto(int sockfd, const void *buf, size_t len, int flags,
                    const struct sockaddr *dest_addr,
                    [[maybe_unused]] socklen_t addrlen) {
  if (flags != 0 || dest_addr != nullptr) return -EINVAL;
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(sockfd);
  if (unlikely(!f)) return -EBADF;
  if (unlikely(f->get_type() != FileType::kSocket)) return -ENOTSOCK;
  Status<size_t> ret = f->Write(
      writable_span(static_cast<const char *>(buf), len), &f->get_off_ref());
  if (!ret) return -ret.error().code();
  return static_cast<ssize_t>(*ret);
}

long usys_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(sockfd);
  if (unlikely(!f)) return -EBADF;
  if (unlikely(f->get_type() != FileType::kSocket)) return -ENOTSOCK;
  Socket *s = static_cast<Socket *>(f);
  Status<std::shared_ptr<Socket>> ret = s->Accept();
  if (!ret) return -ret.error().code();
  if (addr) {
    if (!addrlen || *addrlen < sizeof(sockaddr_in)) return -EINVAL;
    Status<netaddr> na = (*ret)->RemoteAddr();
    if (!na) return -na.error().code();
    sockaddr_in *addr_in = reinterpret_cast<sockaddr_in *>(addr);
    addr_in->sin_family = AF_INET;
    addr_in->sin_port = hton16(na->port);
    addr_in->sin_addr.s_addr = hton32(na->ip);
    *addrlen = sizeof(sockaddr_in);
  }
  return ftbl.Insert(std::move(*ret));
}

long usys_shutdown(int sockfd, int how) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(sockfd);
  if (unlikely(!f)) return -EBADF;
  if (unlikely(f->get_type() != FileType::kSocket)) return -ENOTSOCK;
  Socket *s = static_cast<Socket *>(f);
  Status<void> ret = s->Shutdown(how);
  if (!ret) return -ret.error().code();
  return 0;
}

long usys_listen(int sockfd, int backlog) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(sockfd);
  if (unlikely(!f)) return -EBADF;
  if (unlikely(f->get_type() != FileType::kSocket)) return -ENOTSOCK;
  Socket *s = static_cast<Socket *>(f);
  Status<void> ret = s->Listen(backlog);
  if (!ret) return -ret.error().code();
  return 0;
}

}  // namespace junction
