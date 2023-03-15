// tcp_socket.h - TCP socket
#pragma once

extern "C" {
#include <sys/ioctl.h>
}

#include <memory>
#include <variant>

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
  TCPSocket(int flags = 0) noexcept
      : Socket(flags), state_(SocketState::kSockUnbound) {}
  TCPSocket(rt::TCPConn conn, int flags = 0) noexcept
      : Socket(flags),
        state_(SocketState::kSockConnected),
        v_(std::move(conn)) {}

  ~TCPSocket() override = default;

  Status<void> Bind(netaddr addr) override {
    // TODO(jsf): this should in theory reserve a port in the socket table
    if (unlikely(state_ != SocketState::kSockUnbound)) return MakeError(EINVAL);
    addr_ = addr;
    state_ = SocketState::kSockBound;
    return {};
  }

  Status<void> Listen(int backlog) override {
    Status<rt::TCPQueue> ret = rt::TCPQueue::Listen(addr_, backlog);
    if (unlikely(!ret)) return MakeError(ret);
    if (is_nonblocking()) ret->SetNonBlocking(true);
    v_ = std::move(*ret);
    state_ = SocketState::kSockListening;
    if (IsPollSourceSetup()) SetupPollSource();
    return {};
  }

  Status<void> Connect(netaddr addr) override {
    // Some applications probe the nonblocking socket by calling connect()
    if (state_ == SocketState::kSockConnected) {
      if (!is_nonblocking()) return MakeError(EISCONN);
      return TcpConn().GetStatus();
    }

    if (unlikely(state_ != SocketState::kSockUnbound &&
                 state_ != SocketState::kSockBound))
      return MakeError(EINVAL);
    Status<rt::TCPConn> ret;
    if (is_nonblocking())
      ret = rt::TCPConn::DialNonBlocking(addr_, addr);
    else
      ret = rt::TCPConn::Dial(addr_, addr);
    if (unlikely(!ret)) return MakeError(ret);
    v_ = std::move(*ret);
    state_ = SocketState::kSockConnected;
    if (IsPollSourceSetup()) SetupPollSource();
    if (is_nonblocking()) return TcpConn().GetStatus();
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

  Status<void> Ioctl(unsigned long request, [[maybe_unused]] char *argp) override {
    switch (request) {
      case FIONBIO:
        set_flags(get_flags() | kFlagNonblock);
        return {};
      default:
        LOG_ONCE(WARN) << "Unsupported ioctl request: " << request;
        return MakeError(EINVAL);
    }
  }

  Status<netaddr> RemoteAddr() override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(ENOTCONN);
    return TcpConn().RemoteAddr();
  }

  Status<netaddr> LocalAddr() override {
    switch (state_) {
      case SocketState::kSockUnbound:
      case SocketState::kSockBound:
        return addr_;
      case SocketState::kSockConnected:
        return TcpConn().LocalAddr();
      case SocketState::kSockListening:
        return TcpQueue().LocalAddr();
      default:
        std::unreachable();
    }
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
    PollSource &s = get_poll_source();
    if (state_ == SocketState::kSockListening)
      TcpQueue().InstallPollSource(PollSourceSet, PollSourceClear,
                                   reinterpret_cast<unsigned long>(&s));
    else if (state_ == SocketState::kSockConnected)
      TcpConn().InstallPollSource(PollSourceSet, PollSourceClear,
                                  reinterpret_cast<unsigned long>(&s));
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

  [[nodiscard]] rt::TCPConn &TcpConn() { return std::get<rt::TCPConn>(v_); }
  [[nodiscard]] rt::TCPQueue &TcpQueue() { return std::get<rt::TCPQueue>(v_); }

  SocketState state_;
  netaddr addr_{0, 0};
  std::atomic_bool is_shut_{false};
  std::variant<rt::TCPConn, rt::TCPQueue> v_;
};

}  // namespace junction
