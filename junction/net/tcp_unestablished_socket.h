// tcp_unestablished_socket.h - TCP socket that has been created but waiting to
// establish a connectiong with a remote endpoint
#pragma once

#include <memory>

#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/net/socket.h"
#include "junction/net/tcp_established_socket.h"
#include "junction/net/tcp_listener_socket.h"

namespace junction {

class TCPUnestablishedSocket : public Socket {
 public:
  TCPUnestablishedSocket() noexcept : Socket() {}
  ~TCPUnestablishedSocket() override = default;

  Status<std::shared_ptr<Socket>> Bind(netaddr addr) {
    return std::make_shared<TCPListenerSocket>(addr);
  }

  Status<std::shared_ptr<Socket>> Connect(netaddr addr) {
    Status<rt::TCPConn> ret = rt::TCPConn::Dial({0, 0}, addr);
    if (unlikely(!ret)) return MakeError(ret);
    return std::make_shared<TCPEstablishedSocket>(std::move(*ret));
  }
};

}  // namespace junction
