#include "junction/net/socket.h"

#include "junction/bindings/log.h"

namespace junction {

Status<size_t> Socket::GetSockOpt(int level, int optname,
                                  std::span<std::byte> value) const {
  if (level == IPPROTO_TCP || level == IPPROTO_UDP)
    return GetSockOptImpl(level, optname, value);
  if (level == IPPROTO_IP) return GetIPSocketOptions(optname, value);
  if (level != SOL_SOCKET) return MakeError(EINVAL);
  switch (optname) {
    case SO_REUSEPORT:
      if (value.size() < sizeof(int)) return MakeError(EINVAL);
      *reinterpret_cast<int *>(value.data()) = reuse_port() ? 1 : 0;
      return sizeof(int);
    case SO_RCVTIMEO:
      if (value.size() < sizeof(timeval)) return MakeError(EINVAL);
      *reinterpret_cast<timeval *>(value.data()) = read_timeout_.Timeval();
      return sizeof(timeval);
    case SO_SNDTIMEO:
      if (value.size() < sizeof(timeval)) return MakeError(EINVAL);
      *reinterpret_cast<timeval *>(value.data()) = write_timeout_.Timeval();
      return sizeof(timeval);
    default:
      return GetSockOptImpl(level, optname, value);
  }
}

Status<void> Socket::SetSockOpt(int level, int optname,
                                std::span<const std::byte> value) {
  if (level == IPPROTO_TCP || level == IPPROTO_UDP)
    return SetSockOptImpl(level, optname, value);
  if (level == IPPROTO_IP) return SetIPSocketOptions(optname, value);
  if (level != SOL_SOCKET) return MakeError(EINVAL);
  switch (optname) {
    case SO_REUSEADDR:
    case SO_REUSEPORT:
      reuse_port_ = *reinterpret_cast<const int *>(value.data());
      return {};
    case SO_RCVTIMEO:
      if (value.size() < sizeof(timeval)) return MakeError(EINVAL);
      read_timeout_ =
          Duration(*reinterpret_cast<const timeval *>(value.data()));
      return {};
    case SO_SNDTIMEO:
      if (value.size() < sizeof(timeval)) return MakeError(EINVAL);
      write_timeout_ =
          Duration(*reinterpret_cast<const timeval *>(value.data()));
      return {};
    default:
      return SetSockOptImpl(level, optname, value);
  }
}

Status<void> IPSocket::SetIPSocketOptions(int optname,
                                          std::span<const std::byte> optval) {
  if (optval.size() < sizeof(int)) return MakeError(EINVAL);
  const int val = *reinterpret_cast<const int *>(optval.data());
  if (optname == IP_RECVTOS) {
    if (!val)
      remove_socket_option(kSockOptRecvTos);
    else
      add_socket_option(kSockOptRecvTos);
  } else if (optname == IP_PKTINFO) {
    if (!val)
      remove_socket_option(kSockOptPktInfo);
    else
      add_socket_option(kSockOptPktInfo);
  } else if (optname == IP_MTU_DISCOVER) {
    LOG_ONCE(WARN) << "Setsockopt: ignoring IP_MTU_DISCOVER directive";
  } else {
    return MakeError(EINVAL);
  }
  return {};
}

Status<size_t> IPSocket::GetIPSocketOptions(int optname,
                                            std::span<std::byte> value) const {
  if (value.size() < sizeof(int)) return MakeError(EINVAL);
  int *optval = reinterpret_cast<int *>(value.data());
  if (optname == IP_RECVTOS) {
    *optval = socket_options() & kSockOptRecvTos ? 1 : 0;
  } else if (optname == IP_PKTINFO) {
    *optval = socket_options() & kSockOptPktInfo ? 1 : 0;
  } else if (optname == IP_MTU) {
    LOG_ONCE(WARN) << "Getsockopt: reporting default (non-path specific) MTU";
    *optval = udp_get_payload_size();
  } else {
    return MakeError(EINVAL);
  }
  return sizeof(int);
}

}  // namespace junction