// tcp_listener_socket.h - TCP socket for listening to incoming connections
#pragma once

#include <atomic>
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
  TCPListenerSocket(netaddr addr) noexcept : Socket(), addr_(addr) {}
  virtual ~TCPListenerSocket() {}

  virtual Status<void> Listen(int backlog) override;
  virtual Status<std::shared_ptr<Socket>> Accept() override;
  virtual Status<void> Shutdown(int how) override;

 private:
  netaddr addr_;
  std::atomic_bool is_shut_{false};
  rt::TCPQueue listen_q_;
};

}  // namespace junction
