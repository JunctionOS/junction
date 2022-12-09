// tcp_listener_socket.h - TCP socket for listening to incoming connections
extern "C" {
#include <sys/socket.h>
}

#pragma once

#include <memory>
#include <optional>
#include <span>

#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/net/socket.h"

namespace junction {

// TODO(girfan): Prevent these classes from being copied and write move ctors.
class TCPListenerSocket : public Socket {
 public:
  TCPListenerSocket(uint32_t ip, uint16_t port) noexcept
      : Socket(), ip_(ip), port_(port) {}
  virtual ~TCPListenerSocket() {}

  virtual Status<void> Listen(int backlog) override;
  virtual Status<std::shared_ptr<Socket>> Accept(
      std::optional<uint32_t *> ip, std::optional<uint16_t *> port) override;
  virtual Status<void> Shutdown(int how) override;

 private:
  uint32_t ip_;
  uint16_t port_;
  bool is_listening_{false};
  rt::TCPQueue listen_q_;
};

}  // namespace junction
