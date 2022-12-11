#include "junction/net/tcp_listener_socket.h"

#include <memory>
#include <optional>

#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/net/socket.h"
#include "junction/net/tcp_socket.h"

namespace junction {

Status<void> TCPListenerSocket::Listen(int backlog) {
  Status<rt::TCPQueue> ret = rt::TCPQueue::Listen(addr_, backlog);
  if (!ret) return MakeError(ret);
  listen_q_ = std::move(*ret);
  return {};
}

Status<std::shared_ptr<Socket>> TCPListenerSocket::Accept() {
  if (unlikely(!listen_q_.Valid())) return MakeError(EINVAL);
  Status<rt::TCPConn> ret = listen_q_.Accept();
  if (!ret) return MakeError(ret);
  return std::make_shared<TCPSocket>(std::move(*ret));
}

Status<void> TCPListenerSocket::Shutdown([[maybe_unused]] int how) {
  if (!listen_q_.Valid()) return MakeError(ENOTCONN);
  bool shutdown = false;
  if (is_shut_.compare_exchange_strong(shutdown, true)) listen_q_.Shutdown();
  return {};
}

}  // namespace junction
