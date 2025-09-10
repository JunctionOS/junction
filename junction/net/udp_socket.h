// udp_socket.h - UDP socket
#pragma once

#include <atomic>
#include <memory>
#include <span>

#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/net/caladan_poll.h"
#include "junction/net/socket.h"
#include "junction/snapshot/cereal.h"

namespace junction {

class UDPSocket : public Socket {
 public:
  UDPSocket(int flags = 0) noexcept : Socket(flags) {}
  ~UDPSocket() override = default;

  Status<void> Bind(const SockAddrPtr addr) override {
    assert(addr);
    if (unlikely(conn_.is_valid())) return MakeError(EINVAL);
    Status<netaddr> na = addr.ToNetAddr();
    if (unlikely(!na)) return MakeError(na);
    Status<rt::BindToken> ret = rt::BindToken::AllocateUDP(*na, reuse_port_);
    if (unlikely(!ret)) return MakeError(ret);
    bind_token_ = std::move(*ret);
    return {};
  }

  Status<void> Connect(const SockAddrPtr addr) override {
    if (unlikely(conn_.is_valid())) return MakeError(EISCONN);
    Status<netaddr> raddr = addr.ToNetAddr();
    if (unlikely(!raddr)) return MakeError(raddr);

    Status<rt::UDPConn> ret;
    if (bind_token_.is_valid())
      ret = bind_token_.DialUDP(*raddr);
    else
      ret = rt::UDPConn::Dial({}, *raddr);

    if (unlikely(!ret)) return MakeError(ret);
    InstallConn(std::move(*ret));
    return {};
  }

  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off) override {
    if (unlikely(!conn_.is_valid())) return MakeError(EINVAL);
    return conn_.Read(buf);
  }

  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off) override {
    if (unlikely(!conn_.is_valid())) return MakeError(EDESTADDRREQ);
    return conn_.Write(buf);
  }

  Status<size_t> Writev(std::span<const iovec> iov,
                        [[maybe_unused]] off_t *off) override {
    if (unlikely(!conn_.is_valid())) return MakeError(EDESTADDRREQ);
    return conn_.WritevTo(iov, nullptr, is_nonblocking());
  }

  Status<size_t> ReadFrom(std::span<std::byte> buf, SockAddrPtr raddr,
                          bool peek, bool nonblocking) override {
    if (unlikely(!conn_.is_valid())) {
      if (Status<void> ret = TrySetupConn(false); !ret) return MakeError(ret);
    }
    netaddr ra;
    Status<size_t> ret =
        conn_.ReadFrom(buf, raddr ? &ra : nullptr, peek, nonblocking);
    if (unlikely(!ret)) return ret;
    if (raddr) raddr.FromNetAddr(ra);
    return ret;
  }

  Status<size_t> ReadvFrom(std::span<iovec> iov, SockAddrPtr raddr, bool peek,
                           bool nonblocking) override {
    if (unlikely(!conn_.is_valid())) {
      if (Status<void> ret = TrySetupConn(false); !ret) return MakeError(ret);
    }
    netaddr ra;
    Status<size_t> ret =
        conn_.ReadvFrom(iov, raddr ? &ra : nullptr, peek, nonblocking);
    if (unlikely(!ret)) return ret;
    if (raddr) raddr.FromNetAddr(ra);
    return ret;
  }

  Status<size_t> WriteTo(std::span<const std::byte> buf,
                         const SockAddrPtr raddr, bool nonblocking) override {
    if (!conn_.is_valid()) {
      if (Status<void> ret = TrySetupConn(true); !ret) return MakeError(ret);
    }
    if (raddr) {
      Status<netaddr> ra = raddr.ToNetAddr();
      if (unlikely(!ra)) return MakeError(ra);
      return conn_.WriteTo(buf, &*ra, nonblocking);
    }
    return conn_.WriteTo(buf, nullptr, nonblocking);
  }

  Status<size_t> WritevTo(std::span<const iovec> iov, const SockAddrPtr raddr,
                          bool nonblocking) override {
    if (!conn_.is_valid()) {
      if (Status<void> ret = TrySetupConn(true); !ret) return MakeError(ret);
    }

    if (raddr) {
      Status<netaddr> ra = raddr.ToNetAddr();
      if (unlikely(!ra)) return MakeError(ra);
      return conn_.WritevTo(iov, &*ra, nonblocking);
    }
    return conn_.WritevTo(iov, nullptr, nonblocking);
  }

  Status<void> Shutdown([[maybe_unused]] int how) override {
    if (unlikely(!conn_.is_valid())) return MakeError(EINVAL);
    bool shutdown = false;
    if (is_shut_.compare_exchange_strong(shutdown, true)) conn_.Shutdown();
    return {};
  }

  Status<void> RemoteAddr(SockAddrPtr raddr) const override {
    if (unlikely(!conn_.is_valid())) return MakeError(EINVAL);
    assert(raddr);
    Status<netaddr> ret = conn_.RemoteAddr();
    if (unlikely(!ret)) return MakeError(ret);
    raddr.FromNetAddr(*ret);
    return {};
  }

  Status<void> LocalAddr(SockAddrPtr laddr) const override {
    assert(laddr);
    if (bind_token_.is_valid()) {
      laddr.FromNetAddr(bind_token_.LocalAddr());
      return {};
    }
    if (unlikely(!conn_.is_valid())) return MakeError(EINVAL);
    Status<netaddr> ret = conn_.LocalAddr();
    if (unlikely(!ret)) return MakeError(ret);
    laddr.FromNetAddr(*ret);
    return {};
  }

  Status<int> GetSockOpt(int level, int optname) const override {
    if (level != SOL_SOCKET) return MakeError(EINVAL);
    switch (optname) {
      case SO_DOMAIN:
        return AF_INET;
      case SO_PROTOCOL:
        return IPPROTO_UDP;
      case SO_TYPE:
        return SOCK_DGRAM;
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
        if (conn_.is_valid() || bind_token_.is_valid())
          return MakeError(EINVAL);
        reuse_port_ = *reinterpret_cast<const int *>(optval.data());
        return {};
      default:
        return MakeError(EINVAL);
    }
  }

 private:
  void SetupPollSource() override {
    if (!conn_.is_valid()) return;
    PollSource &s = get_poll_source();
    conn_.InstallPollSource(PollSourceSet, PollSourceClear,
                            reinterpret_cast<unsigned long>(&s));
  }

  void NotifyFlagsChanging(unsigned int oldflags,
                           unsigned int newflags) override {
    if (!conn_.is_valid()) return;
    if ((oldflags & kFlagNonblock) == (newflags & kFlagNonblock)) return;
    conn_.SetNonBlocking((newflags & kFlagNonblock) > 0);
  }

  inline void InstallConn(rt::UDPConn &&new_conn) {
    assert(!conn_.is_valid());
    assert(!bind_token_.is_valid());
    conn_ = std::move(new_conn);
    if (is_nonblocking()) conn_.SetNonBlocking(true);
    if (IsPollSourceSetup()) SetupPollSource();
  }

  // UDP sockets can be initiated on the fly without calling connect.
  Status<void> TrySetupConn(bool is_outbound) {
    assert(!conn_.is_valid());
    // An attempt to read without an already defined local port does not make
    // sense, just return an error.
    if (!bind_token_.is_valid() && !is_outbound) return MakeError(EINVAL);

    Status<rt::UDPConn> ret;
    if (bind_token_.is_valid()) {
      ret = bind_token_.ListenUDP();
    } else {
      ret = rt::UDPConn::Listen({});
    }

    if (unlikely(!ret)) return MakeError(ret);
    InstallConn(std::move(*ret));
    return {};
  }

  friend class cereal::access;

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<Socket>(this), conn_.is_valid(),
       bind_token_.is_valid(), reuse_port_);
    if (conn_.is_valid())
      ar(conn_.LocalAddr(), conn_.RemoteAddr(), is_shut_);
    else if (bind_token_.is_valid())
      ar(bind_token_.LocalAddr());
  }

  template <class Archive>
  void load(Archive &ar) {
    bool conn_is_valid, bind_token_is_valid;
    ar(cereal::base_class<Socket>(this), conn_is_valid, bind_token_is_valid,
       reuse_port_);

    netaddr laddr, raddr;

    if (bind_token_is_valid) {
      assert(!conn_.is_valid());
      ar(laddr);
      Status<rt::BindToken> ret =
          rt::BindToken::AllocateUDP(laddr, reuse_port_);
      if (unlikely(!ret)) {
        LOG(ERR) << "failed to restore UDP bind token @ " << laddr.ip << ":"
                 << laddr.port;
        BUG();
      }
      bind_token_ = std::move(*ret);
      return;
    }

    if (!conn_is_valid) return;

    ar(laddr, raddr, is_shut_);

    Status<rt::UDPConn> ret;
    if (raddr.ip == 0 && raddr.port == 0) {
      ret = rt::UDPConn::Listen(laddr);
      if (unlikely(!ret)) {
        LOG(ERR) << "failed to restore UDP listen socket @ " << laddr.ip << ":"
                 << laddr.port;
        BUG();
      }
    } else {
      ret = rt::UDPConn::Dial(laddr, raddr);
      if (unlikely(!ret)) {
        LOG(ERR) << "failed to restore UDP socket  " << laddr.ip << ":"
                 << laddr.port << " <-> " << raddr.ip << ":" << raddr.port;
        BUG();
      }
    }

    if (is_shut_) ret->Shutdown();
    InstallConn(std::move(*ret));
  }

  // This may or may not be valid. If UDPSocket is created without a rt::UDPConn
  // then this will be invalid until WriteTo is called.
  // Otherwise, UDPSocket will be created with a valid rt::UDPConn which will be
  // stored here (as a result of Bind/Connect calls).
  rt::UDPConn conn_;
  rt::BindToken bind_token_;
  std::atomic_bool is_shut_{false};
  bool reuse_port_{false};
};

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::UDPSocket);
