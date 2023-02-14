// tcp_listener_socket.h - TCP socket for listening to incoming connections
#pragma once

#include <atomic>
#include <memory>
#include <optional>

#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/net/socket.h"

namespace junction {

class TCPListenerSocket : public Socket {
 public:
  TCPListenerSocket(netaddr addr) noexcept : Socket(), addr_(addr) {}
  ~TCPListenerSocket() override = default;

  Status<void> Listen(int backlog) override {
    Status<rt::TCPQueue> ret = rt::TCPQueue::Listen(addr_, backlog);
    if (unlikely(!ret)) return MakeError(ret);
    listen_q_ = std::move(*ret);
    if (IsPollSourceSetup()) SetupPollSource();
    return {};
  }
  Status<std::shared_ptr<Socket>> Accept() override {
    if (unlikely(!listen_q_.is_valid())) return MakeError(EINVAL);
    Status<rt::TCPConn> ret = listen_q_.Accept();
    if (unlikely(!ret)) return MakeError(ret);
    return std::make_shared<TCPEstablishedSocket>(std::move(*ret));
  }
  Status<void> Shutdown(int how) override {
    if (unlikely(!listen_q_.is_valid())) return MakeError(ENOTCONN);
    bool shutdown = false;
    if (is_shut_.compare_exchange_strong(shutdown, true)) listen_q_.Shutdown();
    return {};
  }

 private:
  virtual void SetupPollSource() override {
    if (!listen_q_.is_valid()) return;
    listen_q_.InstallPollSource(PollSourceSet, PollSourceClear,
                                reinterpret_cast<unsigned long>(&poll_));
  }

  netaddr addr_;
  std::atomic_bool is_shut_{false};
  rt::TCPQueue listen_q_;
};

}  // namespace junction
