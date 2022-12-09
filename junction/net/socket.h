// socket.h - Socket interface
extern "C" {
#include <sys/socket.h>
}

#pragma once

#include <memory>
#include <optional>

#include "junction/base/error.h"
#include "junction/kernel/file.h"

namespace junction {

class Socket : public File {
 public:
  Socket() : File(FileType::kSocket, 0 /* flags */, kModeReadWrite) {}
  virtual ~Socket() {}

  // Returns a shared pointer to a specialized socket that is bound; a
  // specialized socket in this case is TCPListenerSocket.
  virtual Status<std::shared_ptr<Socket>> Bind(uint32_t ip, uint16_t port) {
    return MakeError(EINVAL);
  }
  // Returns a shared pointer to a specialized socket connected to the remote
  // endpoint; a specialized socket in this case could be either TCPSocket or
  // UDPSocket.
  virtual Status<std::shared_ptr<Socket>> Connect(uint32_t ip, uint16_t port) {
    return MakeError(EINVAL);
  }
  virtual Status<std::shared_ptr<Socket>> Accept(
      std::optional<uint32_t *> ip, std::optional<uint16_t *> port) {
    return MakeError(EINVAL);
  }
  virtual Status<void> Listen(int backlog) { return MakeError(EINVAL); }
  virtual Status<void> Shutdown(int how) { return MakeError(EINVAL); }
};

}  // namespace junction
