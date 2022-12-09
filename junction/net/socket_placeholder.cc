#include "junction/net/socket_placeholder.h"

#include <memory>

#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/net/tcp_listener_socket.h"
#include "junction/net/tcp_socket.h"

namespace junction {

SocketPlaceholder::SocketPlaceholder(Token, int domain, int type,
                                     int protocol) noexcept
    : Socket(), domain_(domain), type_(type), protocol_(protocol) {}

Status<std::shared_ptr<SocketPlaceholder>> SocketPlaceholder::Create(
    int domain, int type, int protocol) {
  if (unlikely(domain != AF_INET || type != SOCK_STREAM))
    return MakeError(EINVAL);
  return std::make_shared<SocketPlaceholder>(Token{}, domain, type, protocol);
}

Status<std::shared_ptr<Socket>> SocketPlaceholder::Bind(netaddr addr) {
  return std::make_shared<TCPListenerSocket>(addr);
}

Status<std::shared_ptr<Socket>> SocketPlaceholder::Connect(netaddr addr) {
  Status<rt::TCPConn> ret = rt::TCPConn::Dial({0, 0}, addr);
  if (!ret) return MakeError(ret);
  return std::make_shared<TCPSocket>(std::move(*ret));
}

}  // namespace junction
