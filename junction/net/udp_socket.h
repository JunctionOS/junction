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
    Status<rt::BindToken> token = rt::BindToken::AllocateUDP(*na, reuse_port());
    if (unlikely(!token)) return MakeError(token);
    Status<rt::UDPConn> ret = token->ListenUDP();
    if (unlikely(!ret)) return MakeError(ret);
    InstallConn(std::move(*ret));
    return {};
  }

  Status<void> Connect(const SockAddrPtr addr) override {
    netaddr laddr;
    if (conn_.is_valid()) {
      netaddr remote = conn_.RemoteAddr();
      if (unlikely(remote.ip || remote.port)) return MakeError(EISCONN);
      laddr = conn_.LocalAddr();
    } else {
      laddr = {0, 0};
    }
    Status<netaddr> raddr = addr.ToNetAddr();
    if (unlikely(!raddr)) return MakeError(raddr);
    Status<rt::UDPConn> ret = rt::UDPConn::Dial(laddr, *raddr);
    if (unlikely(!ret)) return MakeError(ret);
    InstallConn(std::move(*ret));
    return {};
  }

  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off) override {
    if (unlikely(!conn_.is_valid())) return MakeError(EINVAL);
    rt::RuntimeWaitqTimeout timeout(read_timeout());
    return conn_.Read(buf);
  }

  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off) override {
    if (unlikely(!conn_.is_valid())) return MakeError(EDESTADDRREQ);
    rt::RuntimeWaitqTimeout timeout(write_timeout());
    return conn_.Write(buf);
  }

  Status<size_t> Writev(std::span<const iovec> iov,
                        [[maybe_unused]] off_t *off) override {
    if (unlikely(!conn_.is_valid())) return MakeError(EDESTADDRREQ);
    rt::RuntimeWaitqTimeout timeout(write_timeout());
    return conn_.WritevTo(iov, nullptr, is_nonblocking());
  }

  Status<size_t> ReadFrom(std::span<std::byte> buf, SockAddrPtr raddr,
                          bool peek, bool nonblocking) override {
    if (unlikely(!conn_.is_valid())) return MakeError(EINVAL);
    netaddr ra;
    rt::RuntimeWaitqTimeout timeout(read_timeout());
    Status<size_t> ret =
        conn_.ReadFrom(buf, raddr ? &ra : nullptr, peek, nonblocking);
    if (unlikely(!ret)) return ret;
    if (raddr) raddr.FromNetAddr(ra);
    return ret;
  }

  Status<size_t> ReadvFrom(std::span<iovec> iov, SockAddrPtr raddr, bool peek,
                           bool nonblocking) override {
    if (unlikely(!conn_.is_valid())) return MakeError(EINVAL);
    netaddr ra;
    rt::RuntimeWaitqTimeout timeout(read_timeout());
    Status<size_t> ret =
        conn_.ReadvFrom(iov, raddr ? &ra : nullptr, peek, nonblocking);
    if (unlikely(!ret)) return ret;
    if (raddr) raddr.FromNetAddr(ra);
    return ret;
  }

  Status<size_t> WriteTo(std::span<const std::byte> buf,
                         const SockAddrPtr raddr, bool nonblocking) override {
    if (!conn_.is_valid()) {
      if (Status<void> ret = TrySetupConn(); !ret) return MakeError(ret);
    }
    rt::RuntimeWaitqTimeout timeout(write_timeout());
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
      if (Status<void> ret = TrySetupConn(); !ret) return MakeError(ret);
    }
    rt::RuntimeWaitqTimeout timeout(write_timeout());
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
    if (unlikely(!conn_.is_valid())) return MakeError(EINVAL);
    Status<netaddr> ret = conn_.LocalAddr();
    if (unlikely(!ret)) return MakeError(ret);
    laddr.FromNetAddr(*ret);
    return {};
  }

 protected:
  Status<size_t> GetSockOptImpl(int level, int optname,
                                std::span<std::byte> value) const override {
    if (level != SOL_SOCKET) return MakeError(EINVAL);
    int ret;
    switch (optname) {
      case SO_DOMAIN:
        ret = AF_INET;
        break;
      case SO_PROTOCOL:
        ret = IPPROTO_UDP;
        break;
      case SO_TYPE:
        ret = SOCK_DGRAM;
        break;
      default:
        return MakeError(EINVAL);
    }
    if (value.size() < sizeof(int)) return MakeError(EINVAL);
    *reinterpret_cast<int *>(value.data()) = ret;
    return sizeof(int);
  }

 private:
  void SetupPollSource() override {
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
    if (conn_.is_valid() && IsPollSourceSetup())
      conn_.InstallPollSource(nullptr, nullptr, 0);
    conn_ = std::move(new_conn);
    if (is_nonblocking()) conn_.SetNonBlocking(true);
    if (IsPollSourceSetup()) SetupPollSource();
  }

  // UDP sockets can be initiated on the fly without calling bind/connect.
  Status<void> TrySetupConn() {
    assert(!conn_.is_valid());
    Status<rt::UDPConn> ret = rt::UDPConn::Listen({});
    if (unlikely(!ret)) return MakeError(ret);
    InstallConn(std::move(*ret));
    return {};
  }

  friend class cereal::access;

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<Socket>(this), conn_.is_valid());
    if (conn_.is_valid()) ar(conn_.LocalAddr(), conn_.RemoteAddr(), is_shut_);
  }

  template <class Archive>
  void load(Archive &ar) {
    bool conn_is_valid;
    ar(cereal::base_class<Socket>(this), conn_is_valid);
    if (!conn_is_valid) return;

    netaddr laddr, raddr;

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
  std::atomic_bool is_shut_{false};
};

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::UDPSocket);
