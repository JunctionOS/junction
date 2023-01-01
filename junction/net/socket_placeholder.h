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
  ~SocketPlaceholder() override = default;

  static Status<std::shared_ptr<SocketPlaceholder>> Create(int domain, int type,
                                                           int protocol);
  Status<std::shared_ptr<Socket>> Bind(netaddr addr) override;
  Status<std::shared_ptr<Socket>> Connect(netaddr addr) override;

 private:
  int domain_;
  int type_;
  int protocol_;
};

}  // namespace junction
