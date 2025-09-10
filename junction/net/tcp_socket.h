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

  ~TCPSocket() = default;

  Status<void> Bind(const SockAddrPtr addr) override {
    if (unlikely(state_ != SocketState::kSockUnbound)) return MakeError(EINVAL);
    Status<netaddr> na = addr.ToNetAddr();
    if (unlikely(!na)) return MakeError(na);
    Status<rt::BindToken> ret = rt::BindToken::AllocateTCP(*na, reuse_port_);
    if (unlikely(!ret)) return MakeError(ret);
    v_ = std::move(*ret);
    state_ = SocketState::kSockBound;
    return {};
  }

  Status<void> Listen(int backlog) override {
    Status<rt::TCPQueue> ret;
    if (state_ == SocketState::kSockBound) {
      ret = BindToken().ListenTCP(backlog);
    } else if (state_ == SocketState::kSockUnbound) {
      ret = rt::TCPQueue::Listen({}, backlog);
    } else {
      return MakeError(EINVAL);
    }
    if (unlikely(!ret)) return MakeError(ret);
    if (is_nonblocking()) ret->SetNonBlocking(true);
    v_ = std::move(*ret);
    state_ = SocketState::kSockListening;
    backlog_ = backlog;
    if (IsPollSourceSetup()) SetupPollSource();
    return {};
  }

  Status<void> Connect(const SockAddrPtr addr) override {
    // Some applications probe the nonblocking socket by calling connect()
    if (state_ == SocketState::kSockConnected) {
      if (!is_nonblocking()) return MakeError(EISCONN);
      return TcpConn().GetStatus();
    }

    if (unlikely(state_ == SocketState::kSockListening))
      return MakeError(EINVAL);
    Status<netaddr> na = addr.ToNetAddr();
    if (unlikely(!na)) return MakeError(na);
    Status<rt::TCPConn> ret;
    if (state_ == SocketState::kSockBound) {
      ret = BindToken().DialTCP(*na, is_nonblocking());
    } else if (is_nonblocking()) {
      ret = rt::TCPConn::DialNonBlocking({}, *na);
    } else {
      ret = rt::TCPConn::Dial({}, *na);
    }

    if (unlikely(!ret)) return MakeError(ret);
    v_ = std::move(*ret);
    state_ = SocketState::kSockConnected;
    if (IsPollSourceSetup()) SetupPollSource();
    if (is_nonblocking()) return TcpConn().GetStatus();
    return {};
  }

  Status<std::shared_ptr<Socket>> Accept(SockAddrPtr addr, int flags) override {
    if (unlikely(state_ != SocketState::kSockListening))
      return MakeError(EINVAL);
    Status<rt::TCPConn> ret = TcpQueue().Accept();
    if (unlikely(!ret)) return MakeError(ret);
    if (flags & kFlagNonblock) ret->SetNonBlocking(true);
    if (addr) addr.FromNetAddr(ret->RemoteAddr());
    return std::make_shared<TCPSocket>(std::move(*ret), flags);
  }

  [[nodiscard]] Status<size_t> get_input_bytes() const override {
    if (state_ != SocketState::kSockConnected) return MakeError(EINVAL);
    return TcpConn().GetInputBytes();
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

  Status<void> RemoteAddr(SockAddrPtr ptr) const override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(ENOTCONN);
    if (unlikely(!ptr)) return MakeError(EINVAL);
    ptr.FromNetAddr(TcpConn().RemoteAddr());
    return {};
  }

  Status<void> LocalAddr(SockAddrPtr ptr) const override {
    if (unlikely(!ptr)) return MakeError(EINVAL);
    switch (state_) {
      case SocketState::kSockUnbound:
      case SocketState::kSockBound:
        ptr.FromNetAddr(BindToken().LocalAddr());
        break;
      case SocketState::kSockConnected:
        ptr.FromNetAddr(TcpConn().LocalAddr());
        break;
      case SocketState::kSockListening:
        ptr.FromNetAddr(TcpQueue().LocalAddr());
        break;
      default:
        std::unreachable();
    }
    return {};
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

  Status<size_t> ReadFrom(std::span<std::byte> buf, SockAddrPtr raddr,
                          bool peek, bool nonblocking) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) raddr.FromNetAddr(TcpConn().RemoteAddr());
    return TcpConn().Read(buf, peek, nonblocking);
  }

  Status<size_t> WriteTo(std::span<const std::byte> buf,
                         const SockAddrPtr raddr, bool nonblocking) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) return MakeError(EISCONN);
    return TcpConn().Write(buf, nonblocking);
  }

  Status<size_t> WritevTo(std::span<const iovec> iov, const SockAddrPtr raddr,
                          bool nonblocking) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) return MakeError(EISCONN);
    return TcpConn().Writev(iov, nonblocking);
  }

  Status<size_t> Writev(std::span<const iovec> iov,
                        [[maybe_unused]] off_t *off = nullptr) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    return TcpConn().Writev(iov);
  }

  Status<size_t> ReadvFrom(std::span<iovec> iov, SockAddrPtr raddr, bool peek,
                           bool nonblocking) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) raddr.FromNetAddr(TcpConn().RemoteAddr());
    return TcpConn().Readv(iov, peek, nonblocking);
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
      case SO_ERROR:
        if (state_ == SocketState::kSockConnected) {
          Status<void> ret = TcpConn().GetStatus();
          return ret ? 0 : ret.error().code();
        }
        /* fallthrough */
      default:
        return MakeError(EINVAL);
    }
  }

  Status<void> SetSockOpt(int level, int optname,
                          std::span<const std::byte> optval) override {
    if (level != SOL_SOCKET) return MakeError(EINVAL);
    switch (optname) {
      case SO_REUSEADDR:
      case SO_REUSEPORT:
        if (state_ != SocketState::kSockUnbound) return MakeError(EINVAL);
        reuse_port_ = *reinterpret_cast<const int *>(optval.data());
        return {};
      default:
        return MakeError(EINVAL);
    }
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

  [[nodiscard]] rt::TCPConn &TcpConn() {
    assert(state_ == SocketState::kSockConnected);
    return std::get<rt::TCPConn>(v_);
  }
  [[nodiscard]] rt::TCPQueue &TcpQueue() {
    assert(state_ == SocketState::kSockListening);
    return std::get<rt::TCPQueue>(v_);
  }
  [[nodiscard]] const rt::TCPConn &TcpConn() const {
    assert(state_ == SocketState::kSockConnected);
    return std::get<rt::TCPConn>(v_);
  }
  [[nodiscard]] const rt::TCPQueue &TcpQueue() const {
    assert(state_ == SocketState::kSockListening);
    return std::get<rt::TCPQueue>(v_);
  }
  [[nodiscard]] rt::BindToken &BindToken() {
    assert(state_ == SocketState::kSockBound);
    return std::get<rt::BindToken>(v_);
  }
  [[nodiscard]] const rt::BindToken &BindToken() const {
    assert(state_ == SocketState::kSockBound);
    return std::get<rt::BindToken>(v_);
  }

  friend class cereal::access;

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<Socket>(this), state_);

    switch (state_) {
      case SocketState::kSockBound:
        ar(BindToken().LocalAddr(), reuse_port_);
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
      netaddr addr;
      ar(addr, reuse_port_);
      Status<rt::BindToken> ret = rt::BindToken::AllocateTCP(addr, reuse_port_);
      BUG_ON(!ret);
      v_ = std::move(*ret);
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
        char lstr[IP_ADDR_STR_LEN], rstr[IP_ADDR_STR_LEN];
        char *lip = ip_addr_to_str(laddr.ip, lstr);
        char *rip = ip_addr_to_str(raddr.ip, rstr);
        LOG(ERR) << "failed to restore TCP socket  " << lip << ":" << laddr.port
                 << " <-> " << rip << ":" << raddr.port;
        BUG();
      }
      v_ = std::move(*c);
    } else {
      assert(state_ == SocketState::kSockListening);
      netaddr addr;
      ar(addr, is_shut_, backlog_);
      Status<rt::TCPQueue> q = rt::TCPQueue::Listen(addr, backlog_);
      if (unlikely(!q)) {
        char str[IP_ADDR_STR_LEN];
        char *ip = ip_addr_to_str(addr.ip, str);
        LOG(ERR) << "failed to restore TCP listen socket @ " << ip << ":"
                 << addr.port;
        BUG();
      }
      if (is_nonblocking()) q->SetNonBlocking(true);
      if (is_shut_) q->Shutdown();
      v_ = std::move(*q);
    }

    if (IsPollSourceSetup()) SetupPollSource();
  }

  SocketState state_;
  int backlog_;
  bool reuse_port_{false};
  std::atomic_bool is_shut_{false};
  std::variant<rt::TCPConn, rt::TCPQueue, rt::BindToken> v_;
};

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::TCPSocket);
