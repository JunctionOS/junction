// tcp_established_socket.h - TCP socket in a connected state
#pragma once

#include <span>

#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/net/caladan_poll.h"
#include "junction/net/socket.h"

namespace junction {

class TCPEstablishedSocket : public Socket {
 public:
  TCPEstablishedSocket(rt::TCPConn conn) noexcept
      : Socket(), conn_(std::move(conn)) {
    conn_.InstallPollSource(
        PollSourceSet, PollSourceClear,
        reinterpret_cast<unsigned long>(&get_poll_source()));
  }
  ~TCPEstablishedSocket() override = default;

  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off = nullptr) override {
    return conn_.Read(buf);
  }
  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off = nullptr) override {
    return conn_.Write(buf);
  }
  virtual Status<size_t> ReadFrom(std::span<std::byte> buf,
                                  netaddr *raddr) override {
    if (raddr) *raddr = conn_.RemoteAddr();
    return Read(buf);
  }
  virtual Status<size_t> WriteTo(std::span<const std::byte> buf,
                                 const netaddr *raddr) override {
    if (raddr) return MakeError(EISCONN);
    return Write(buf);
  }
  Status<void> Shutdown(int how) override { return conn_.Shutdown(how); }
  Status<netaddr> RemoteAddr() override { return conn_.RemoteAddr(); }
  Status<netaddr> LocalAddr() override { return conn_.LocalAddr(); }

 private:
  rt::TCPConn conn_;
};

}  // namespace junction
