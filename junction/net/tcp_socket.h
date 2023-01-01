// tcp_socket.h - TCP socket in a connected state
#pragma once

#include <memory>
#include <span>

#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/net/socket.h"

namespace junction {

class TCPSocket : public Socket {
 public:
  TCPSocket(rt::TCPConn conn) : Socket(), conn_(std::move(conn)) {}
  ~TCPSocket() override = default;

  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off) override {
    return conn_.Read(buf);
  }
  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off) override {
    return conn_.Write(buf);
  }
  Status<void> Shutdown(int how) override { return conn_.Shutdown(how); }
  Status<netaddr> RemoteAddr() override { return conn_.RemoteAddr(); }

 private:
  rt::TCPConn conn_;
};

}  // namespace junction
