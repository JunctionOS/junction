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
#include "junction/snapshot/cereal.h"

namespace junction {

class TCPSocket : public Socket {
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
    backlog_ = backlog;
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

  Status<netaddr> RemoteAddr() const override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(ENOTCONN);
    return TcpConn().RemoteAddr();
  }

  Status<netaddr> LocalAddr() const override {
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

  virtual Status<size_t> ReadFrom(std::span<std::byte> buf, netaddr *raddr,
                                  bool peek) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) *raddr = TcpConn().RemoteAddr();
    if (peek) return TcpConn().ReadPeek(buf);
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

  Status<size_t> Readv(std::span<iovec> iov,
                       [[maybe_unused]] off_t *off) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    return TcpConn().Readv(iov);
  }

  Status<int> GetSockOpt(int level, int optname) const override {
    if (level != SOL_SOCKET) return MakeError(EINVAL);
    switch (optname) {
      case SO_ACCEPTCONN:
        return state_ == SocketState::kSockListening ? 1 : 0;
      case SO_DOMAIN:
        return AF_INET;
      case SO_PROTOCOL:
        return IPPROTO_TCP;
      case SO_TYPE:
        return SOCK_STREAM;
      default:
        return MakeError(EINVAL);
    }
  }

 private:
  enum class SocketState {
    kSockUnbound,
    kSockBound,
    kSockListening,
    kSockConnected
  };

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
  [[nodiscard]] const rt::TCPConn &TcpConn() const {
    return std::get<rt::TCPConn>(v_);
  }
  [[nodiscard]] const rt::TCPQueue &TcpQueue() const {
    return std::get<rt::TCPQueue>(v_);
  }

  friend class cereal::access;

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<Socket>(this), state_);

    switch (state_) {
      case SocketState::kSockBound:
        ar(addr_);
        break;
      case SocketState::kSockConnected:
        ar(TcpConn().LocalAddr(), TcpConn().RemoteAddr());
        break;
      case SocketState::kSockListening:
        ar(TcpQueue().LocalAddr(), is_shut_, backlog_);
        break;
      default:
        break;
    }
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(cereal::base_class<Socket>(this), state_);

    if (state_ == SocketState::kSockUnbound) return;
    if (state_ == SocketState::kSockBound) {
      ar(addr_);
      return;
    }

    if (state_ == SocketState::kSockConnected) {
      netaddr laddr, raddr;
      ar(laddr, raddr);
      Status<rt::TCPConn> c;
      if (is_nonblocking()) {
        c = rt::TCPConn::DialNonBlocking(laddr, raddr);
      } else {
        LOG(WARN) << "re-establishing TCP connection (may hang)";
        c = rt::TCPConn::Dial(laddr, raddr);
      }

      if (unlikely(!c)) {
        LOG(ERR) << "failed to restore TCP socket  " << laddr.ip << ":"
                 << laddr.port << " <-> " << raddr.ip << ":" << raddr.port;
        BUG();
      }
      v_ = std::move(*c);
    } else {
      assert(state_ == SocketState::kSockListening);
      ar(addr_, is_shut_, backlog_);
      Status<rt::TCPQueue> q = rt::TCPQueue::Listen(addr_, backlog_);
      if (unlikely(!q)) {
        LOG(ERR) << "failed to restore TCP listen socket @ " << addr_.ip << ":"
                 << addr_.port;
        BUG();
      }
      if (is_nonblocking()) q->SetNonBlocking(true);
      if (is_shut_) q->Shutdown();
      v_ = std::move(*q);
    }

    if (IsPollSourceSetup()) SetupPollSource();
  }

  SocketState state_;
  netaddr addr_{0, 0};
  int backlog_;
  std::atomic_bool is_shut_{false};
  std::variant<rt::TCPConn, rt::TCPQueue> v_;
};

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::TCPSocket);
