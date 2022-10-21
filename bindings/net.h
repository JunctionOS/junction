// net.h - support for networking

#pragma once

extern "C" {
#include <base/stddef.h>
#include <runtime/tcp.h>
#include <runtime/udp.h>
}

#include <cstddef>
#include <span>

#include "error.h"
#include "io.h"

namespace rt {

// UDP Connections.
class UDPConn {
 public:
  ~UDPConn() {
    if (c_) udp_close(c_);
  }

  // Move support.
  UDPConn(UDPConn &&c) noexcept : c_(c.c_) { c.c_ = nullptr; }
  UDPConn &operator=(UDPConn &&c) noexcept {
    c_ = c.c_;
    c.c_ = nullptr;
    return *this;
  }

  // The maximum possible payload size (with the maximum MTU).
  static constexpr size_t kMaxPayloadSize = UDP_MAX_PAYLOAD;

  // Creates a UDP connection between a local and remote address.
  static Status<UDPConn> Dial(netaddr laddr, netaddr raddr) {
    udpconn_t *c;
    int ret = udp_dial(laddr, raddr, &c);
    if (ret) return MakeError(-ret);
    return UDPConn(c);
  }

  // Creates a UDP connection that receives all packets on a local port.
  static Status<UDPConn> Listen(netaddr laddr) {
    udpconn_t *c;
    int ret = udp_listen(laddr, &c);
    if (ret) return MakeError(-ret);
    return UDPConn(c);
  }

  // Gets the MTU-limited payload size.
  static size_t PayloadSize() { return static_cast<size_t>(udp_payload_size); }

  // Gets the local UDP address.
  netaddr LocalAddr() const { return udp_local_addr(c_); }
  // Gets the remote UDP address.
  netaddr RemoteAddr() const { return udp_remote_addr(c_); }

  // Adjusts the length of buffer limits.
  Status<void> SetBuffers(int read_mbufs, int write_mbufs) {
    int ret = udp_set_buffers(c_, read_mbufs, write_mbufs);
    if (ret) MakeError(-ret);
    return {};
  }

  // Reads a datagram and gets from remote address.
  Status<size_t> ReadFrom(std::span<std::byte> buf, netaddr *raddr) {
    ssize_t ret = udp_read_from(c_, buf.data(), buf.size_bytes(), raddr);
    if (ret <= 0) return MakeError(-ret);
    return ret;
  }
  // Writes a datagram and sets to remote address.
  Status<size_t> WriteTo(std::span<const std::byte> buf,
                                  const netaddr *raddr) {
    ssize_t ret = udp_write_to(c_, buf.data(), buf.size_bytes(), raddr);
    if (ret < 0) return MakeError(-ret);
    return ret;
  }

  // Reads a datagram.
  Status<size_t> Read(std::span<std::byte> buf) {
    ssize_t ret = udp_read(c_, buf.data(), buf.size_bytes());
    if (ret <= 0) return MakeError(-ret);
    return ret;
  }
  // Writes a datagram.
  Status<size_t> Write(std::span<const std::byte> buf) {
    ssize_t ret = udp_write(c_, buf.data(), buf.size_bytes());
    if (ret < 0) return MakeError(-ret);
    return ret;
  }

  // Shutdown the socket (no more receives).
  void Shutdown() { udp_shutdown(c_); }

 private:
  explicit UDPConn(udpconn_t *c) noexcept : c_(c) {}

  // disable copy.
  UDPConn(const UDPConn &) = delete;
  UDPConn &operator=(const UDPConn &) = delete;

  udpconn_t *c_;
};

// TCP connections.
class TCPConn : public VectorIO {
  friend class TCPQueue;

 public:
  ~TCPConn() { tcp_close(c_); }

  // Move support.
  TCPConn(TCPConn &&c) noexcept : c_(c.c_) { c.c_ = nullptr; }
  TCPConn &operator=(TCPConn &&c) noexcept {
    c_ = c.c_;
    c.c_ = nullptr;
    return *this;
  }

  // Creates a TCP connection between a local and remote address.
  static Status<TCPConn> Dial(netaddr laddr, netaddr raddr) {
    tcpconn_t *c;
    int ret = tcp_dial(laddr, raddr, &c);
    if (ret) MakeError(-ret);
    return TCPConn(c);
  }

  // Creates a TCP connection with affinity to a CPU index.
  static Status<TCPConn> DialAffinity(unsigned int cpu,
                                               netaddr raddr) {
    tcpconn_t *c;
    int ret = tcp_dial_affinity(cpu, raddr, &c);
    if (ret) return MakeError(-ret);
    return TCPConn(c);
  }

  // Creates a new TCP connection with affinity to another TCP connection.
  static Status<TCPConn> DialAffinity(const TCPConn &cin,
                                               netaddr raddr) {
    tcpconn_t *c;
    int ret = tcp_dial_conn_affinity(cin.c_, raddr, &c);
    if (ret) return MakeError(-ret);
    return TCPConn(c);
  }

  // Gets the local TCP address.
  netaddr LocalAddr() const { return tcp_local_addr(c_); }
  // Gets the remote TCP address.
  netaddr RemoteAddr() const { return tcp_remote_addr(c_); }

  // Reads from the TCP stream.
  Status<size_t> Read(std::span<std::byte> buf) {
    ssize_t ret = tcp_read(c_, buf.data(), buf.size_bytes());
    if (ret <= 0) MakeError(-ret);
    return ret;
  }
  // Writes to the TCP stream.
  Status<size_t> Write(std::span<const std::byte> buf) {
    ssize_t ret = tcp_write(c_, buf.data(), buf.size_bytes());
    if (ret < 0) MakeError(-ret);
    return ret;
  }

  // Reads a vector from the TCP stream.
  Status<size_t> Readv(std::span<const iovec> iov) {
    ssize_t ret = tcp_readv(c_, iov.data(), iov.size());
    if (ret <= 0) MakeError(-ret);
    return ret;
  }
  // Writes a vector to the TCP stream.
  Status<size_t> Writev(std::span<const iovec> iov) {
    ssize_t ret = tcp_writev(c_, iov.data(), iov.size());
    if (ret < 0) MakeError(-ret);
    return ret;
  }

  // Gracefully shutdown the TCP connection.
  Status<void> Shutdown(int how) {
    int ret = tcp_shutdown(c_, how);
    if (ret < 0) MakeError(-ret);
    return {};
  }
  // Ungracefully force the TCP connection to shutdown.
  void Abort() { tcp_abort(c_); }

 private:
  explicit TCPConn(tcpconn_t *c) noexcept : c_(c) {}

  // disable copy.
  TCPConn(const TCPConn &) = delete;
  TCPConn &operator=(const TCPConn &) = delete;

  tcpconn_t *c_;
};

// TCP listener queues.
class TCPQueue {
 public:
  ~TCPQueue() { tcp_qclose(q_); }

  // Move support.
  TCPQueue(TCPQueue &&q) noexcept : q_(q.q_) { q.q_ = nullptr; }
  TCPQueue &operator=(TCPQueue &&q) noexcept {
    q_ = q.q_;
    q.q_ = nullptr;
    return *this;
  }

  // Creates a TCP listener queue.
  static Status<TCPQueue> Listen(netaddr laddr, int backlog) {
    tcpqueue_t *q;
    int ret = tcp_listen(laddr, backlog, &q);
    if (ret) return MakeError(-ret);
    return TCPQueue(q);
  }

  // Accept a connection from the listener queue.
  Status<TCPConn> Accept() {
    tcpconn_t *c;
    int ret = tcp_accept(q_, &c);
    if (ret) MakeError(-ret);
    return TCPConn(c);
  }

  // Shutdown the listener queue; any blocked Accept() returns a nullptr.
  void Shutdown() { tcp_qshutdown(q_); }

 private:
  explicit TCPQueue(tcpqueue_t *q) noexcept : q_(q) {}

  // disable copy.
  TCPQueue(const TCPQueue &) = delete;
  TCPQueue &operator=(const TCPQueue &) = delete;

  tcpqueue_t *q_;
};

}  // namespace rt
