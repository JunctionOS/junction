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

  Status<void> Bind(netaddr addr) override {
    if (unlikely(conn_.is_valid())) return MakeError(EINVAL);
    Status<rt::UDPConn> ret = rt::UDPConn::Listen(addr);
    if (unlikely(!ret)) return MakeError(ret);
    conn_ = std::move(*ret);
    if (is_nonblocking()) conn_.SetNonBlocking(true);
    if (IsPollSourceSetup()) SetupPollSource();
    return {};
  }

  Status<void> Connect(netaddr addr) override {
    netaddr laddr;
    if (conn_.is_valid()) {
      netaddr remote = conn_.RemoteAddr();
      if (unlikely(remote.ip || remote.port)) return MakeError(EINVAL);
      laddr = conn_.LocalAddr();
    } else {
      laddr = {0, 0};
    }
    Status<rt::UDPConn> ret = rt::UDPConn::Dial(laddr, addr);
    if (unlikely(!ret)) return MakeError(ret);
    ReplaceConn(std::move(*ret));
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

  Status<size_t> ReadFrom(std::span<std::byte> buf, netaddr *raddr,
                          bool peek) override {
    if (unlikely(!conn_.is_valid())) return MakeError(EINVAL);
    return conn_.ReadFrom(buf, raddr, peek);
  }

  Status<size_t> WriteTo(std::span<const std::byte> buf,
                         const netaddr *raddr) override {
    if (!conn_.is_valid()) {
      Status<rt::UDPConn> ret = rt::UDPConn::Listen({0, 0});
      if (unlikely(!ret)) return MakeError(ret);
      ReplaceConn(std::move(*ret));
    }
    return conn_.WriteTo(buf, raddr);
  }

  Status<void> Shutdown([[maybe_unused]] int how) override {
    if (unlikely(!conn_.is_valid())) return MakeError(EINVAL);
    bool shutdown = false;
    if (is_shut_.compare_exchange_strong(shutdown, true)) conn_.Shutdown();
    return {};
  }

  Status<netaddr> RemoteAddr() const override {
    if (unlikely(!conn_.is_valid())) return MakeError(EINVAL);
    return conn_.RemoteAddr();
  }

  Status<netaddr> LocalAddr() const override {
    if (unlikely(!conn_.is_valid())) return MakeError(EINVAL);
    return conn_.LocalAddr();
  }

  // TODO(jsf): Writev, WritevTo, Readv

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

  inline void ReplaceConn(rt::UDPConn &&new_conn) {
    if (conn_.is_valid() && IsPollSourceSetup())
      conn_.InstallPollSource(nullptr, nullptr, 0);
    conn_ = std::move(new_conn);
    if (is_nonblocking()) conn_.SetNonBlocking(true);
    if (IsPollSourceSetup()) SetupPollSource();
  }

  friend class cereal::access;

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<Socket>(this), conn_.is_valid());
    if (conn_.is_valid()) ar(conn_.LocalAddr(), conn_.RemoteAddr(), is_shut_);
  }

  template <class Archive>
  void load(Archive &ar) {
    bool is_valid;
    ar(cereal::base_class<Socket>(this), is_valid);
    if (!is_valid) return;

    netaddr laddr;
    netaddr raddr;

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
    ReplaceConn(std::move(*ret));
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
