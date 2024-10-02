
#include "junction/net/netlink.h"

#include <linux/if.h>      // For IFF_* constants (e.g., IFF_UP, IFF_BROADCAST)
#include <linux/if_arp.h>  // For ARPHRD_* constants (e.g., ARPHRD_ETHER)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "junction/base/byte_channel.h"
#include "junction/bindings/log.h"
#include "junction/net/socket.h"

extern "C" {
#include "lib/caladan/runtime/defs.h"
}

// Very incomplete version of netlink, just barely enough to get Go's
// net.Interfaces() package running.

namespace junction {

class NetlinkSocket : public Socket {
 public:
  NetlinkSocket(int flag) : Socket(flag) {}
  ~NetlinkSocket() override = default;

  Status<size_t> ReadFrom(std::span<std::byte> buf, SockAddrPtr raddr,
                          bool peek = false,
                          [[maybe_unused]] bool nonblocking = false) override {
    return data_.Read(buf, peek);
  }

  Status<size_t> WriteTo(std::span<const std::byte> buf,
                         const SockAddrPtr raddr,
                         [[maybe_unused]] bool nonblocking = false) override {
    const nlmsghdr *nlh = reinterpret_cast<const nlmsghdr *>(buf.data());

    rt::ScopedLock g(lock_);

    switch (nlh->nlmsg_type) {
      case RTM_GETLINK:
        RespondToLinkQuery();
        break;
      case RTM_GETADDR:
        ResponseToAddrQuery();
        break;
      default:
        return MakeError(EINVAL);
    }

    return std::min(buf.size(), static_cast<size_t>(NLA_ALIGN(nlh->nlmsg_len)));
  }

  Status<void> Bind(const SockAddrPtr addr) override {
    if (!addr || addr.Family() != AF_NETLINK) return MakeError(EINVAL);
    addr_ = *reinterpret_cast<const struct sockaddr_nl *>(addr.Ptr());
    return {};
  }

  Status<void> LocalAddr(SockAddrPtr addr) const override {
    assert(addr);
    std::memcpy(addr.Ptr(), &addr_, std::min(addr.size(), sizeof(addr_)));
    addr.set_size(sizeof(addr_));
    return {};
  }

 private:
  void RespondToLinkQuery() {
    struct {
      nlmsghdr nlh;
      ifinfomsg ifi;
      union {
        struct {
          nlattr name_attr;
          char name[strlen("eth0") + 1];
        };
        unsigned char _bytes[NLA_ALIGN(NLA_HDRLEN + strlen("eth0") + 1)];
      };
      nlmsghdr done_nlh;
    } msg;

    msg.nlh.nlmsg_len = sizeof(nlmsghdr) + sizeof(ifinfomsg) +
                        NLA_ALIGN(NLA_HDRLEN + strlen("eth0") + 1);
    msg.nlh.nlmsg_type = RTM_NEWLINK;
    msg.nlh.nlmsg_flags = NLM_F_MULTI;
    msg.nlh.nlmsg_seq = seq_;
    msg.nlh.nlmsg_pid = 0;  // 0 for kernel responses.

    // Prepare the link information message.
    msg.ifi.ifi_family = AF_INET;
    msg.ifi.ifi_type = ARPHRD_ETHER;  // Ethernet interface type.
    msg.ifi.ifi_index = 0;            // Interface index (e.g., eth0).
    msg.ifi.ifi_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST;
    msg.ifi.ifi_change = 0xFFFFFFFF;  // Specify which flags have changed.

    // Add interface name attribute.
    msg.name_attr.nla_len = NLA_HDRLEN + strlen("eth0") + 1;
    msg.name_attr.nla_type = IFLA_IFNAME;
    strcpy(msg.name, "eth0");

    // Add the "done" message.
    msg.done_nlh.nlmsg_len = sizeof(nlmsghdr);
    msg.done_nlh.nlmsg_type = NLMSG_DONE;
    msg.done_nlh.nlmsg_flags = 0;  // No flags needed for the done message.
    msg.done_nlh.nlmsg_seq =
        seq_++;                  // Use the same sequence number as the request.
    msg.done_nlh.nlmsg_pid = 0;  // 0 for kernel responses.

    Status<size_t> ret = data_.Write(std::as_bytes(std::span{&msg, 1}));
    if (ret != sizeof(msg)) LOG(WARN) << "netlink: failed to respond";
  }

  void ResponseToAddrQuery() {
    struct {
      nlmsghdr nlh;
      ifaddrmsg ifa;
      union {
        struct {
          nlattr addr_attr;
          uint32_t s_addr;
        };
        unsigned char _bytes[NLA_ALIGN(NLA_HDRLEN + sizeof(uint32_t))];
      };
      nlmsghdr done_nlh;
    } msg;

    // Prepare the netlink message header.
    msg.nlh.nlmsg_type = RTM_NEWADDR;
    msg.nlh.nlmsg_flags = NLM_F_MULTI;
    msg.nlh.nlmsg_seq = seq_;
    msg.nlh.nlmsg_pid = 0;
    msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(ifaddrmsg)) +
                        NLA_ALIGN(NLA_HDRLEN + sizeof(uint32_t));

    // Prepare the address information message.
    msg.ifa.ifa_family = AF_INET;
    msg.ifa.ifa_prefixlen = __builtin_popcount(netcfg.netmask);
    msg.ifa.ifa_flags = 0;
    msg.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
    msg.ifa.ifa_index = 0;

    // Prepare the address attribute.
    msg.addr_attr.nla_len = NLA_HDRLEN + sizeof(uint32_t);
    msg.addr_attr.nla_type = IFA_ADDRESS;
    msg.s_addr = hton32(netcfg.addr);

    // Prepare the "done" message.
    msg.done_nlh.nlmsg_len = sizeof(nlmsghdr);
    msg.done_nlh.nlmsg_type = NLMSG_DONE;
    msg.done_nlh.nlmsg_flags = 0;  // No flags needed for the done message.
    msg.done_nlh.nlmsg_seq =
        seq_++;                  // Use the same sequence number as the request.
    msg.done_nlh.nlmsg_pid = 0;  // 0 for kernel responses.

    Status<size_t> ret = data_.Write(std::as_bytes(std::span{&msg, 1}));
    if (ret != sizeof(msg)) LOG(WARN) << "netlink: failed to respond";
  }

  rt::Mutex lock_;
  ByteChannel data_{kPageSize};
  struct sockaddr_nl addr_;
  uint32_t seq_{1};
};

Status<std::shared_ptr<Socket>> CreateNetlinkSocket(int type, int flags,
                                                    int protocol) {
  if (type != SOCK_RAW || protocol != NETLINK_ROUTE) return MakeError(EINVAL);
  return std::make_shared<NetlinkSocket>(flags);
}

}  // namespace junction