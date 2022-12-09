extern "C" {
#include <arpa/inet.h>
#include <sys/socket.h>
}

#include <memory>
#include <optional>

#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/net/socket.h"
#include "junction/net/tcp_listener_socket.h"
#include "junction/net/tcp_socket.h"

namespace junction {

Status<void> TCPListenerSocket::Listen(int backlog) {
  Status<rt::TCPQueue> ret = rt::TCPQueue::Listen({ip_, port_}, backlog);
  if (!ret) return MakeError(ret);
  listen_q_ = std::move(*ret);
  is_listening_ = true;
  return {};
}

Status<std::shared_ptr<Socket>> TCPListenerSocket::Accept(
    std::optional<uint32_t *> ip, std::optional<uint16_t *> port) {
  if (!is_listening_) return MakeError(EINVAL);
  Status<rt::TCPConn> ret = listen_q_.Accept();
  if (!ret) return MakeError(ret);
  netaddr sock_addr = ret->RemoteAddr();
  if (ip.has_value() && port.has_value()) {
    *(*ip) = htonl(sock_addr.ip);
    *(*port) = htons(sock_addr.port);
  }
  return std::make_shared<TCPSocket>(std::move(*ret));
}

Status<void> TCPListenerSocket::Shutdown([[maybe_unused]] int how) {
  listen_q_.Shutdown();
  return {};
}

}  // namespace junction
