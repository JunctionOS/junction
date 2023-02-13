// socket.h - Socket interface

#pragma once

#include <memory>
#include <optional>

#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/kernel/file.h"

namespace junction {

constexpr unsigned int kSockNonblock = SOCK_NONBLOCK;
constexpr unsigned int kSockCloseOnExec = SOCK_CLOEXEC;

constexpr unsigned int kMsgNoSignal = MSG_NOSIGNAL;

class Socket : public File {
 public:
  Socket() : File(FileType::kSocket, 0 /* flags */, kModeReadWrite) {}
  ~Socket() override = default;

  // Returns a shared pointer to a specialized socket that is bound; a
  // specialized socket in this case would be a TCPListenerSocket or
  // UDPUnestablishedSocket.
  virtual Status<std::shared_ptr<Socket>> Bind(netaddr addr) {
    return MakeError(EINVAL);
  }
  // Returns a shared pointer to a specialized socket connected to the remote
  // endpoint; a specialized socket in this case could be either
  // TCPEstablishedSocket or UDPEstablishedSocket.
  virtual Status<std::shared_ptr<Socket>> Connect(netaddr addr) {
    return MakeError(EINVAL);
  }
  virtual Status<size_t> ReadFrom(std::span<std::byte> buf, netaddr *raddr) {
    return MakeError(ENOTCONN);
  }
  virtual Status<size_t> WriteTo(std::span<const std::byte> buf,
                                 const netaddr *raddr) {
    return MakeError(ENOTCONN);
  }
  virtual Status<std::shared_ptr<Socket>> Accept() {
    return MakeError(ENOTCONN);
  }
  virtual Status<void> Listen(int backlog) { return MakeError(ENOTCONN); }
  virtual Status<void> Shutdown(int how) { return MakeError(ENOTCONN); }
  virtual Status<netaddr> RemoteAddr() { return MakeError(ENOTCONN); }
  virtual Status<netaddr> LocalAddr() { return MakeError(ENOTCONN); }
};

}  // namespace junction
