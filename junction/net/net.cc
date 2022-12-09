extern "C" {
#include <netinet/in.h>
#include <sys/socket.h>
}

#include <memory>

#include "junction/base/io.h"
#include "junction/bindings/log.h"
#include "junction/kernel/file.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/net/socket.h"
#include "junction/net/socket_placeholder.h"

namespace junction {

// TODO(girfan): Fix the "restrict" keyword for all the net syscalls.
long usys_socket(int domain, int type, int protocol) {
  Status<std::shared_ptr<Socket>> ret =
      SocketPlaceholder::Create(domain, type, protocol);
  if (unlikely(!ret)) return -ret.error().code();
  FileTable &ftbl = myproc().get_file_table();
  return ftbl.Insert(std::move(*ret));
}

long usys_bind(int sockfd, const struct sockaddr *addr,
               [[maybe_unused]] socklen_t addrlen) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(sockfd);
  if (unlikely(!f)) return -EBADF;
  if (unlikely(f->get_type() != FileType::kSocket)) return -ENOTSOCK;
  Socket *s = static_cast<Socket *>(f);
  const struct sockaddr_in *addr_in =
      reinterpret_cast<const struct sockaddr_in *>(addr);
  Status<std::shared_ptr<Socket>> ret =
      s->Bind(addr_in->sin_addr.s_addr, addr_in->sin_port);
  if (!ret) return -ret.error().code();
  ftbl.InsertAt(sockfd, std::move(*ret));
  return 0;
}

long usys_connect(int sockfd, const struct sockaddr *addr,
                  [[maybe_unused]] socklen_t addrlen) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(sockfd);
  if (unlikely(!f)) return -EBADF;
  if (unlikely(f->get_type() != FileType::kSocket)) return -ENOTSOCK;
  Socket *s = static_cast<Socket *>(f);
  const struct sockaddr_in *addr_in =
      reinterpret_cast<const struct sockaddr_in *>(addr);
  Status<std::shared_ptr<Socket>> ret =
      s->Connect(addr_in->sin_addr.s_addr, addr_in->sin_port);
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

long usys_accept(int sockfd, struct sockaddr *addr,
                 [[maybe_unused]] socklen_t *addrlen) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(sockfd);
  if (unlikely(!f)) return -EBADF;
  if (unlikely(f->get_type() != FileType::kSocket)) return -ENOTSOCK;
  Socket *s = static_cast<Socket *>(f);
  Status<std::shared_ptr<File>> ret;
  if (addr && addrlen) {
    struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in *>(addr);
    ret = s->Accept(&(addr_in->sin_addr.s_addr), &(addr_in->sin_port));
  } else {
    ret = s->Accept(std::nullopt, std::nullopt);
  }
  if (!ret) return -ret.error().code();
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
