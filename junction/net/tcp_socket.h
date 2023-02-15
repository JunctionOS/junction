// tcp_socket.h - TCP socket
#pragma once

#include <memory>

#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/net/caladan_poll.h"
#include "junction/net/socket.h"

namespace junction {

class TCPSocket : public Socket {
  enum class SocketState {
    kSockUnbound,
    kSockBound,
    kSockListening,
    kSockConnected
  };

 public:
  TCPSocket() noexcept : Socket(), state_(SocketState::kSockUnbound) {}
  TCPSocket(rt::TCPConn conn, int flags = 0) noexcept
      : Socket(flags),
        state_(SocketState::kSockConnected),
        conn_(std::move(conn)) {}

  ~TCPSocket() override = default;

  Status<void> Bind(netaddr addr) override {
    // TODO(jsf): this should in theory reserve a port in the socket table
    if (unlikely(state_ != SocketState::kSockUnbound)) return MakeError(EINVAL);
    addr_ = addr;
    state_ = SocketState::kSockBound;
    return {};
  }

  Status<void> Listen(int backlog) override {
    // TODO(jsf): support ephemeral port in Caladan
    if (unlikely(state_ != SocketState::kSockBound)) return MakeError(EINVAL);
    Status<rt::TCPQueue> ret = rt::TCPQueue::Listen(addr_, backlog);
    if (unlikely(!ret)) return MakeError(ret);
    if (get_flags() & kFlagNonblock) ret->SetNonBlocking(true);
    listen_q_ = std::move(*ret);
    state_ = SocketState::kSockListening;
    if (IsPollSourceSetup()) SetupPollSource();
    return {};
  }

  Status<void> Connect(netaddr addr) override {
    if (unlikely(state_ != SocketState::kSockUnbound &&
                 state_ != SocketState::kSockBound))
      return MakeError(EINVAL);
    Status<rt::TCPConn> ret;
    if (get_flags() & kFlagNonblock)
      ret = rt::TCPConn::DialNonBlocking(addr_, addr);
    else
      ret = rt::TCPConn::Dial(addr_, addr);
    if (unlikely(!ret)) return MakeError(ret);
    conn_ = std::move(*ret);
    state_ = SocketState::kSockConnected;
    if (IsPollSourceSetup()) SetupPollSource();
    return {};
  }

  Status<std::shared_ptr<Socket>> Accept(int flags) override {
    if (unlikely(state_ != SocketState::kSockListening))
      return MakeError(EINVAL);
    Status<rt::TCPConn> ret = TcpQueue().Accept();
    if (unlikely(!ret)) return MakeError(ret);
    if (flags & kFlagNonblock) ret->SetNonBlocking(true);
    return std::make_shared<TCPSocket>(std::move(*ret), flags);
  }

  Status<void> Shutdown(int how) override {
    if (state_ == SocketState::kSockConnected) return TcpConn().Shutdown(how);

    if (state_ == SocketState::kSockListening) {
      bool shutdown = false;
      if (is_shut_.compare_exchange_strong(shutdown, true))
        TcpQueue().Shutdown();
      return {};
    }

    return MakeError(ENOTCONN);
  }

  Status<netaddr> RemoteAddr() override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(ENOTCONN);
    return TcpConn().RemoteAddr();
  }

  Status<netaddr> LocalAddr() override {
    if (state_ != SocketState::kSockConnected) return addr_;
    return TcpConn().LocalAddr();
  }

  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off = nullptr) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    return TcpConn().Read(buf);
  }

  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off = nullptr) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    return TcpConn().Write(buf);
  }

  virtual Status<size_t> ReadFrom(std::span<std::byte> buf,
                                  netaddr *raddr) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) *raddr = TcpConn().RemoteAddr();
    return TcpConn().Read(buf);
  }

  virtual Status<size_t> WriteTo(std::span<const std::byte> buf,
                                 const netaddr *raddr) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) return MakeError(EISCONN);
    return TcpConn().Write(buf);
  }

  Status<size_t> WritevTo(std::span<const iovec> iov,
                          const netaddr *raddr) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) return MakeError(EISCONN);
    return TcpConn().Writev(iov);
  }

  Status<size_t> Writev(std::span<const iovec> iov,
                        [[maybe_unused]] off_t *off = nullptr) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    return TcpConn().Writev(iov);
  }

 private:
  void SetupPollSource() override {
    if (state_ == SocketState::kSockListening)
      TcpQueue().InstallPollSource(PollSourceSet, PollSourceClear,
                                   reinterpret_cast<unsigned long>(&poll_));
    else if (state_ == SocketState::kSockConnected)
      TcpConn().InstallPollSource(PollSourceSet, PollSourceClear,
                                  reinterpret_cast<unsigned long>(&poll_));
  }

  void NotifyFlagsChanging(unsigned int oldflags,
                           unsigned int newflags) override {
    if ((oldflags & kFlagNonblock) == (newflags & kFlagNonblock)) return;
    bool nonblocking = (newflags & kFlagNonblock) > 0;
    if (state_ == SocketState::kSockListening)
      TcpQueue().SetNonBlocking(nonblocking);
    else if (state_ == SocketState::kSockConnected)
      TcpConn().SetNonBlocking(nonblocking);
  }

  [[nodiscard]] rt::TCPConn &TcpConn() { return conn_; }
  [[nodiscard]] rt::TCPQueue &TcpQueue() { return listen_q_; }

  SocketState state_;
  netaddr addr_;
  std::atomic_bool is_shut_{false};
  rt::TCPConn conn_;
  rt::TCPQueue listen_q_;
};

}  // namespace junction
