// socket_placeholder.h - Socket that has been created but waiting to be
// specialized
#pragma once

#include <memory>

#include "junction/base/error.h"
#include "junction/net/socket.h"

namespace junction {

class SocketPlaceholder : public Socket {
  class Token {
    // https://abseil.io/tips/134
   private:
    explicit Token() = default;
    friend SocketPlaceholder;
  };

 public:
  SocketPlaceholder(Token, int domain, int type, int protocol) noexcept;
  virtual ~SocketPlaceholder() {}

  static Status<std::shared_ptr<SocketPlaceholder>> Create(int domain, int type,
                                                           int protocol);
  virtual Status<std::shared_ptr<Socket>> Bind(uint32_t ip,
                                               uint16_t port) override;
  virtual Status<std::shared_ptr<Socket>> Connect(uint32_t ip,
                                                  uint16_t port) override;

 private:
  int domain_;
  int type_;
  int protocol_;
};

}  // namespace junction
