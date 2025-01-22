// socket.h - Socket interface

#pragma once

#include <memory>
#include <optional>

#include "junction/base/error.h"
#include "junction/bindings/net.h"
#include "junction/fs/file.h"
#include "junction/snapshot/cereal.h"

namespace junction {

static_assert(kFlagNonblock == SOCK_NONBLOCK);
static_assert(kFlagCloseExec == SOCK_CLOEXEC);

inline constexpr unsigned int kMsgNoSignal = MSG_NOSIGNAL;
inline constexpr unsigned int kMsgPeek = MSG_PEEK;
inline constexpr unsigned int kMsgDontWait = MSG_DONTWAIT;
inline constexpr unsigned int kSockTypeMask = 0xf;

enum class UnixSocketAddressType {
  Unnamed = 0,  // No name assigned.
  Pathname,     // Sockets using a path in the file system
  Abstract,     // Sockets in the abstract namespace
};

enum class SocketState {
  kSockUnbound = 0,
  kSockBound,
  kSockListening,
  kSockConnected
};

using UnixSocketAddr = std::pair<UnixSocketAddressType, std::string>;

// Provide defintions for INET and UNIX socket addresses to avoid pulling in
// Linux headers that conflict with Caladan.
struct sockaddr_in {
  short sin_family;
  unsigned short sin_port;
  struct {
    unsigned int s_addr;
  } sin_addr;
  char sin_zero[8];
};

struct sockaddr_un {
  sa_family_t sun_family;
  char sun_path[108];
};

struct SockAddrPtr {
  explicit SockAddrPtr() : addr(nullptr), addrlen(nullptr) {}
  SockAddrPtr(struct sockaddr *addr, socklen_t *addrlen)
      : addr(addr), addrlen(addrlen) {}
  static const SockAddrPtr asConst(const struct sockaddr *addr,
                                   const socklen_t *addrlen) {
    return SockAddrPtr(const_cast<struct sockaddr *>(addr),
                       const_cast<socklen_t *>(addrlen));
  }

  Status<netaddr> ToNetAddr() const;
  Status<UnixSocketAddr> ToUnixAddr() const;

  void FromUnixAddr(const UnixSocketAddr &uaddr);
  void FromNetAddr(const netaddr &naddr);

  explicit operator bool() const noexcept {
    return addr != nullptr && addrlen != nullptr;
  }

  [[nodiscard]] const sockaddr *Ptr() const { return addr; }
  [[nodiscard]] sockaddr *Ptr() { return addr; }
  [[nodiscard]] int Family() const {
    assert(addr);
    return addr->sa_family;
  }
  [[nodiscard]] size_t size() const {
    assert(addrlen);
    return static_cast<size_t>(*addrlen);
  }
  void set_size(size_t len) {
    assert(addrlen);
    *addrlen = len;
  }

  template <typename AddrType>
  AddrType *asPtr() {
    return reinterpret_cast<AddrType *>(addr);
  }

  struct sockaddr *addr;
  socklen_t *addrlen;
};

class Socket : public File {
 public:
  Socket(int flags = 0)
      : File(FileType::kSocket, flags, FileMode::kReadWrite) {}
  ~Socket() override = default;

  virtual Status<void> Bind(SockAddrPtr addr) { return MakeError(EINVAL); }
  virtual Status<void> Connect(const SockAddrPtr addr) {
    return MakeError(EINVAL);
  }
  virtual Status<size_t> ReadFrom(std::span<std::byte> buf, SockAddrPtr raddr,
                                  bool peek = false, bool nonblocking = false) {
    return MakeError(ENOTCONN);
  }
  virtual Status<size_t> ReadvFrom(std::span<iovec> iov, SockAddrPtr raddr,
                                   bool peek = false,
                                   bool nonblocking = false) {
    return MakeError(ENOTCONN);
  }
  virtual Status<size_t> WriteTo(std::span<const std::byte> buf,
                                 const SockAddrPtr raddr,
                                 bool nonblocking = false) {
    return MakeError(ENOTCONN);
  }

  virtual Status<size_t> WritevTo(std::span<const iovec> iov,
                                  const SockAddrPtr raddr,
                                  bool nonblocking = false) {
    return MakeError(ENOTCONN);
  }

  virtual Status<std::shared_ptr<Socket>> Accept(SockAddrPtr addr,
                                                 int flags = 0) {
    return MakeError(ENOTCONN);
  }
  virtual Status<void> Listen(int backlog) { return MakeError(ENOTCONN); }
  virtual Status<void> Shutdown(int how) { return MakeError(ENOTCONN); }
  virtual Status<void> RemoteAddr(SockAddrPtr addr) const {
    return MakeError(ENOTCONN);
  }
  virtual Status<void> LocalAddr(SockAddrPtr addr) const {
    return MakeError(ENOTCONN);
  }

  virtual Status<int> GetSockOpt(int level, int optname) const {
    return MakeError(EINVAL);
  }

  Status<size_t> Read(std::span<std::byte> buf, off_t *off) override {
    return ReadFrom(buf, SockAddrPtr{});
  }

  Status<size_t> Write(std::span<const std::byte> buf, off_t *off) override {
    return WriteTo(buf, SockAddrPtr{});
  }

  Status<void> Stat(struct stat *statbuf) const override {
    memset(statbuf, 0, sizeof(*statbuf));
    statbuf->st_mode = S_IFSOCK | S_IRUSR;
    return {};
  }

  [[nodiscard]] std::string get_filename() const override { return "socket:"; }

 private:
  friend class cereal::access;

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<File>(this));
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(cereal::base_class<File>(this));
  }
};

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::Socket);
