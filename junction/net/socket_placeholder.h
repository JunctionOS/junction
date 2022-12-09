// socket_placeholder.h - Socket that has been created but waiting to be
// specialized
#pragma once

#include <memory>

#include "junction/base/error.h"
#include "junction/net/socket.h"

namespace junction {

class SocketPlaceholder : public Socket {
 public:
  static Status<std::shared_ptr<SocketPlaceholder>> Create(int domain, int type,
                                                           int protocol);
  virtual ~SocketPlaceholder() {}
  virtual Status<std::shared_ptr<Socket>> Bind(uint32_t ip,
                                               uint16_t port) override;
  virtual Status<std::shared_ptr<Socket>> Connect(uint32_t ip,
                                                  uint16_t port) override;

 private:
  int domain_;
  int type_;
  int protocol_;

  SocketPlaceholder(int domain, int type, int protocol) noexcept;

  struct MakeSharedEnabler;
};

/* This is needed to support std::make_shared for SocketPlaceholder. */
struct SocketPlaceholder::MakeSharedEnabler : public SocketPlaceholder {
  MakeSharedEnabler(int domain, int type, int protocol) noexcept
      : SocketPlaceholder(domain, type, protocol){};
};

}  // namespace junction
