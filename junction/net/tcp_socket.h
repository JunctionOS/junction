// tcp_socket.h - TCP socket in a connected state
extern "C" {
#include <sys/socket.h>
}

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
  virtual ~TCPSocket() {}

  virtual Status<size_t> Read(std::span<std::byte> buf,
                              [[maybe_unused]] off_t *off) override {
    return conn_.Read(buf);
  }
  virtual Status<size_t> Write(std::span<const std::byte> buf,
                               [[maybe_unused]] off_t *off) override {
    return conn_.Write(buf);
  }
  virtual Status<void> Shutdown(int how) override {
    return conn_.Shutdown(how);
  }

 private:
  rt::TCPConn conn_;
};

}  // namespace junction
