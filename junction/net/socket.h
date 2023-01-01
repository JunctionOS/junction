// socket.h - Socket interface

#pragma once

#include <memory>
#include <optional>

#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/kernel/file.h"

namespace junction {

class Socket : public File {
 public:
  Socket() : File(FileType::kSocket, 0 /* flags */, kModeReadWrite) {}
  ~Socket() override = default;

  // Returns a shared pointer to a specialized socket that is bound; a
  // specialized socket in this case is TCPListenerSocket.
  virtual Status<std::shared_ptr<Socket>> Bind(netaddr addr) {
    return MakeError(EINVAL);
  }
  // Returns a shared pointer to a specialized socket connected to the remote
  // endpoint; a specialized socket in this case could be either TCPSocket or
  // UDPSocket.
  virtual Status<std::shared_ptr<Socket>> Connect(netaddr addr) {
    return MakeError(EINVAL);
  }
  virtual Status<std::shared_ptr<Socket>> Accept() { return MakeError(EINVAL); }
  virtual Status<void> Listen(int backlog) { return MakeError(EINVAL); }
  virtual Status<void> Shutdown(int how) { return MakeError(EINVAL); }
  virtual Status<netaddr> RemoteAddr() { return MakeError(EINVAL); }
};

}  // namespace junction
