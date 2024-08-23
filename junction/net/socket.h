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
inline constexpr unsigned int kSockTypeMask = 0xf;

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
                                  bool peek = false) {
    return MakeError(ENOTCONN);
  }
  virtual Status<size_t> WriteTo(std::span<const std::byte> buf,
                                 const SockAddrPtr raddr) {
    return MakeError(ENOTCONN);
  }

  virtual Status<size_t> WritevTo(std::span<const iovec> iov,
                                  const SockAddrPtr raddr) {
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
