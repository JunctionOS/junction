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

class Socket : public File {
 public:
  Socket(int flags = 0) : File(FileType::kSocket, flags, kModeReadWrite) {}
  ~Socket() override = default;

  virtual Status<void> Bind(netaddr addr) { return MakeError(EINVAL); }
  virtual Status<void> Connect(netaddr addr) { return MakeError(EINVAL); }
  virtual Status<size_t> ReadFrom(std::span<std::byte> buf, netaddr *raddr) {
    return MakeError(ENOTCONN);
  }
  virtual Status<size_t> WriteTo(std::span<const std::byte> buf,
                                 const netaddr *raddr) {
    return MakeError(ENOTCONN);
  }

  virtual Status<size_t> WritevTo(std::span<const iovec> iov,
                                  const netaddr *raddr) {
    return MakeError(ENOTCONN);
  }

  virtual Status<std::shared_ptr<Socket>> Accept(int flags = 0) {
    return MakeError(ENOTCONN);
  }
  virtual Status<void> Listen(int backlog) { return MakeError(ENOTCONN); }
  virtual Status<void> Shutdown(int how) { return MakeError(ENOTCONN); }
  virtual Status<netaddr> RemoteAddr() const { return MakeError(ENOTCONN); }
  virtual Status<netaddr> LocalAddr() const { return MakeError(ENOTCONN); }

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
