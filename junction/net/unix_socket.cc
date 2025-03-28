
#include <variant>

#include "junction/fs/pipe.h"
#include "junction/kernel/proc.h"
#include "junction/net/socket.h"
#include "junction/net/unix.h"

namespace junction {

inline constexpr size_t kStreamPipeSize = 4096;
inline constexpr mode_t kMessagePipeSize = 4096;

template <class Archive>
void serialize(Archive &archive, UnixSocketAddr &a) {
  archive(std::get<0>(a), std::get<1>(a));
}

// Table that tracks unix sockets with abstract names (not file-system based)
// for a given type of socket.
template <class SockType>
class UnixSocketTable {
 public:
  Status<void> Insert(std::string_view name, std::weak_ptr<SockType> ino) {
    rt::SpinGuard g(lock_);
    std::weak_ptr<SockType> &mp = tbl_[std::string(name)];
    if (!mp.expired()) return MakeError(EADDRINUSE);
    std::swap(mp, ino);
    return {};
  }

  Status<UnixSocketAddr> NameAndInsert(std::weak_ptr<SockType> ino) {
    constexpr size_t kLength = 40;
    constexpr size_t kTries = 10;
    std::string out;
    out.resize(kLength);
    std::span<std::byte> b(reinterpret_cast<std::byte *>(out.data()), kLength);

    for (size_t i = 0; i < kTries; i++) {
      if (!ReadRandom(b)) {
        LOG(WARN) << "error getting random bytes";
        rt::Sleep(100_us);
        continue;
      }
      for (size_t i = 0; i < kLength; i++)
        out[i] = 'a' + static_cast<uint8_t>(out[i]) % 26;
      if (Insert(out, ino))
        return UnixSocketAddr{UnixSocketAddressType::Abstract, std::move(out)};
    }

    return MakeError(EAGAIN);
  }

  std::weak_ptr<SockType> Find(std::string_view name) {
    rt::SpinGuard g(lock_);
    auto it = tbl_.find(name);
    if (it != tbl_.end()) return it->second;
    return {};
  }

  void Delete(std::string_view name) {
    rt::SpinGuard g(lock_);
    if (auto it = tbl_.find(name); it != tbl_.end()) tbl_.erase(it);
  }

  template <class Archive>
  void serialize(Archive &ar) {
    ar(tbl_);
  }

 private:
  rt::Spin lock_;
  std::map<std::string, std::weak_ptr<SockType>, std::less<>> tbl_;
};

template <class SockType>
class UnixSocketInode : public Inode {
 public:
  UnixSocketInode(std::weak_ptr<SockType> sock)
      : Inode(kTypeSocket | 0600, AllocateInodeNumber()),
        sock_(std::move(sock)) {}

  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    return {};
  }

  // Open a file for this inode.
  Status<std::shared_ptr<File>> Open(
      uint32_t flags, FileMode mode,
      std::shared_ptr<DirectoryEntry> dent) override {
    return MakeError(EINVAL);
  }

  std::weak_ptr<SockType> get_sock() { return sock_; }

  template <class Archive>
  void save(Archive &ar) const {
    ar(sock_);
    ar(cereal::base_class<Inode>(this));
  }

  template <class Archive>
  static void load_and_construct(
      Archive &ar, cereal::construct<UnixSocketInode<SockType>> &construct) {
    std::weak_ptr<SockType> sock_;
    ar(sock_);
    construct(std::move(sock_));
    ar(cereal::base_class<Inode>(construct.ptr()));
  }

 private:
  std::weak_ptr<SockType> sock_;
};

template <class SockType>
Status<std::shared_ptr<SockType>> GetPeer(UnixSocketAddr &addr,
                                          UnixSocketTable<SockType> &tbl) {
  auto &[type, name] = addr;
  std::shared_ptr<SockType> remote;
  if (type == UnixSocketAddressType::Pathname) {
    Status<std::shared_ptr<Inode>> ino = LookupInode(myproc().get_fs(), name);
    if (!ino) return MakeError(ECONNREFUSED);
    UnixSocketInode<SockType> *uino =
        dynamic_cast_guarded<UnixSocketInode<SockType> *>(ino->get());
    if (!uino) return MakeError(ECONNREFUSED);
    remote = uino->get_sock().lock();
  } else {
    remote = tbl.Find(name).lock();
  }
  if (!remote) return MakeError(ECONNREFUSED);
  return remote;
}

//
// Support for Unix datagram sockets
//
using DatagramChannel = MessageChannel<UnixSocketAddr>;

class UnixDatagramSocket;
static UnixSocketTable<UnixDatagramSocket> dgram_tbl;

class UnixDatagramSocket : public Socket {
 public:
  UnixDatagramSocket(int flags = 0) noexcept : Socket(flags) {
    rx_ = std::make_unique<WaitableChannel<DatagramChannel, true>>(
        kMessagePipeSize);
    rx_->AttachReadPoll(&get_poll_source());
  }

  UnixDatagramSocket(
      std::unique_ptr<WaitableChannel<DatagramChannel, true>> chan,
      int flags = 0) noexcept
      : Socket(flags), rx_(std::move(chan)) {
    rx_->AttachReadPoll(&get_poll_source());
  }

  ~UnixDatagramSocket() override {
    if (dent_)
      dent_->RemoveFromParent();
    else if (std::string &name = std::get<1>(local_name_); name.size())
      dgram_tbl.Delete(name);

    rx_->CloseReader(&get_poll_source());
  }

  Status<void> Bind(const SockAddrPtr addr) override {
    if (unlikely(has_name())) return MakeError(EINVAL);
    Status<UnixSocketAddr> a = addr.ToUnixAddr();
    if (unlikely(!a)) return MakeError(a);
    auto &[type, name] = *a;
    std::shared_ptr<UnixSocketInode<UnixDatagramSocket>> ino;
    if (type == UnixSocketAddressType::Pathname)
      ino = std::make_shared<UnixSocketInode<UnixDatagramSocket>>(weak_this());
    if (type == UnixSocketAddressType::Pathname) {
      Status<std::shared_ptr<DirectoryEntry>> ret =
          InsertTo(myproc().get_fs(), name, std::move(ino));
      if (!ret) return MakeError(ret);
      dent_ = std::move(*ret);
    } else {
      Status<void> ret = dgram_tbl.Insert(name, weak_this());
      if (!ret) return MakeError(ret);
    }
    local_name_ = std::move(*a);
    return {};
  }

  Status<void> Connect(const SockAddrPtr addr) override {
    if (unlikely(has_peer())) return MakeError(EISCONN);

    // Parse address.
    Status<UnixSocketAddr> a = addr.ToUnixAddr();
    if (unlikely(!a)) return MakeError(a);

    // Generate a name for this side of the connection, if needed.
    if (!has_name())
      if (Status<void> ret = SetLocalName(); !ret) return ret;

    Status<std::shared_ptr<UnixDatagramSocket>> peer =
        GetPeer<UnixDatagramSocket>(*a, dgram_tbl);
    if (!peer) return MakeError(peer);
    remote_ = *peer;
    connected_ = true;
    return {};
  }

  Status<void> Shutdown(int how) override {
    if (how == SHUT_RD) {
      rx_->CloseReader();
    } else if (how == SHUT_WR) {
      writer_closed_ = true;
    } else if (how == SHUT_RDWR) {
      rx_->CloseReader();
      writer_closed_ = true;
    } else {
      return MakeError(EINVAL);
    }
    return {};
  }

  Status<void> RemoteAddr(SockAddrPtr ptr) const override {
    if (unlikely(!has_peer())) return MakeError(ENOTCONN);
    if (unlikely(!ptr)) return MakeError(EINVAL);

    std::shared_ptr<UnixDatagramSocket> peer = remote_.lock();
    if (!peer) return MakeError(EPIPE);
    ptr.FromUnixAddr(peer->local_name_);
    return {};
  }

  Status<void> LocalAddr(SockAddrPtr ptr) const override {
    if (unlikely(!ptr)) return MakeError(EINVAL);
    ptr.FromUnixAddr(local_name_);
    return {};
  }

  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off = nullptr) override {
    return rx_->Read(buf, is_nonblocking());
  }

  Status<size_t> ReadFrom(std::span<std::byte> buf, SockAddrPtr raddr,
                          bool peek, bool nonblocking) override {
    UnixSocketAddr rem;
    nonblocking |= is_nonblocking();
    Status<size_t> ret = rx_->DoRead(nonblocking, [&](DatagramChannel &chan) {
      return chan.Read(buf, &rem, peek);
    });
    if (ret && raddr) raddr.FromUnixAddr(rem);
    return ret;
  }

  Status<size_t> ReadvFrom(std::span<iovec> iov, SockAddrPtr raddr, bool peek,
                           bool nonblocking) override {
    UnixSocketAddr rem;
    nonblocking |= is_nonblocking();
    Status<size_t> ret = rx_->DoRead(nonblocking, [&](DatagramChannel &chan) {
      return chan.Readv(iov, peek, &rem);
    });
    if (ret && raddr) raddr.FromUnixAddr(rem);
    return ret;
  }

  Status<size_t> Readv(std::span<iovec> iov,
                       [[maybe_unused]] off_t *off) override {
    return rx_->Readv(iov, is_nonblocking());
  }

  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off = nullptr) override {
    if (writer_closed_) return MakeError(EPIPE);
    Status<std::shared_ptr<UnixDatagramSocket>> tmp = ResolvePeer();
    if (!tmp) return MakeError(tmp);
    std::shared_ptr<UnixDatagramSocket> &peer = *tmp;
    return peer->rx_->DoWrite(is_nonblocking(), [&](DatagramChannel &chan) {
      return chan.Write(buf, &local_name_);
    });
  }

  Status<size_t> WriteTo(std::span<const std::byte> buf,
                         const SockAddrPtr raddr, bool nonblocking) override {
    if (writer_closed_) return MakeError(EPIPE);
    Status<std::shared_ptr<UnixDatagramSocket>> tmp = ResolvePeer(raddr);
    if (!tmp) return MakeError(tmp);
    std::shared_ptr<UnixDatagramSocket> &peer = *tmp;
    nonblocking |= is_nonblocking();
    return peer->rx_->DoWrite(nonblocking, [&](DatagramChannel &chan) {
      return chan.Write(buf, &local_name_);
    });
  }

  Status<size_t> Writev(std::span<const iovec> iov,
                        [[maybe_unused]] off_t *off = nullptr) override {
    if (writer_closed_) return MakeError(EPIPE);
    Status<std::shared_ptr<UnixDatagramSocket>> tmp = ResolvePeer();
    if (!tmp) return MakeError(tmp);
    std::shared_ptr<UnixDatagramSocket> &peer = *tmp;
    return peer->rx_->DoWrite(is_nonblocking(), [&](DatagramChannel &chan) {
      return chan.Writev(iov, &local_name_);
    });
  }

  Status<size_t> WritevTo(std::span<const iovec> iov, const SockAddrPtr raddr,
                          bool nonblocking) override {
    if (writer_closed_) return MakeError(EPIPE);
    Status<std::shared_ptr<UnixDatagramSocket>> tmp = ResolvePeer(raddr);
    if (!tmp) return MakeError(tmp);
    std::shared_ptr<UnixDatagramSocket> &peer = *tmp;
    nonblocking |= is_nonblocking();
    return peer->rx_->DoWrite(nonblocking, [&](DatagramChannel &chan) {
      return chan.Writev(iov, &local_name_);
    });
  }

  Status<int> GetSockOpt(int level, int optname) const override {
    if (level != SOL_SOCKET) return MakeError(EINVAL);
    switch (optname) {
      case SO_ACCEPTCONN:
        return 0;
      case SO_DOMAIN:
        return AF_UNIX;
      case SO_PROTOCOL:
        return 0;
      case SO_TYPE:
        return SOCK_DGRAM;
      case SO_ERROR:
        return 0;
      default:
        return MakeError(EINVAL);
    }
  }

  template <class Archive>
  void save(Archive &ar) const {
    ar(rx_);
    ar(cereal::base_class<Socket>(this));
    ar(local_name_, remote_, connected_, dent_, writer_closed_);
  }

  template <class Archive>
  static void load_and_construct(
      Archive &ar, cereal::construct<UnixDatagramSocket> &construct) {
    std::unique_ptr<WaitableChannel<DatagramChannel, true>> chan;
    ar(chan);
    construct(std::move(chan));
    ar(cereal::base_class<Socket>(construct.ptr()));
    UnixDatagramSocket &sock = *construct.ptr();
    ar(sock.local_name_, sock.remote_, sock.connected_, sock.dent_,
       sock.writer_closed_);
  }

 private:
  friend std::pair<int, int> CreatePipeSocket(int flags, bool datagram);
  [[nodiscard]] std::weak_ptr<UnixDatagramSocket> weak_this() {
    return std::static_pointer_cast<UnixDatagramSocket>(shared_from_this());
  }

  Status<std::shared_ptr<UnixDatagramSocket>> ResolvePeer(
      const SockAddrPtr raddr = SockAddrPtr{}) {
    if (has_peer()) {
      if (raddr) return MakeError(EISCONN);
      std::shared_ptr<UnixDatagramSocket> peer = remote_.lock();
      if (!peer) return MakeError(ECONNREFUSED);
      return std::move(peer);
    } else if (!raddr) {
      return MakeError(ENOTCONN);
    }

    // Generate a name for this side of the connection, if needed.
    if (!has_name())
      if (Status<void> ret = SetLocalName(); !ret) return MakeError(ret);

    Status<UnixSocketAddr> addr = raddr.ToUnixAddr();
    if (!addr) return MakeError(addr);
    return GetPeer<UnixDatagramSocket>(*addr, dgram_tbl);
  }

  Status<void> SetLocalName() {
    assert(!has_name());
    Status<UnixSocketAddr> addr = dgram_tbl.NameAndInsert(weak_this());
    if (!addr) return MakeError(addr);
    local_name_ = std::move(*addr);
    return {};
  }

  [[nodiscard]] bool has_name() const {
    return std::get<1>(local_name_).size() > 0;
  }

  [[nodiscard]] bool has_peer() const { return connected_; }

  rt::Spin lock_;
  bool writer_closed_{false};
  bool connected_{false};
  UnixSocketAddr local_name_;
  std::weak_ptr<UnixDatagramSocket> remote_;
  std::unique_ptr<WaitableChannel<DatagramChannel, true>> rx_;
  std::shared_ptr<DirectoryEntry> dent_;
};

//
// Support for Unix SOCK_STREAM connections.
//

struct UnixStreamConnection {
  UnixSocketAddr peer_name;
  std::shared_ptr<StreamPipe> rx;
  std::shared_ptr<StreamPipe> tx;

  template <class Archive>
  void serialize(Archive &ar) {
    ar(peer_name, rx, tx);
  }
};

struct UnixStreamListener {
  UnixStreamListener(int backlog = 4096) : backlog(backlog) {}
  int backlog;
  bool shutdown{false};
  std::list<UnixStreamConnection> accept_q;
  rt::ThreadWaker waiter;

  template <class Archive>
  void serialize(Archive &ar) {
    ar(backlog, shutdown, accept_q);
  }
};

class UnixStreamSocket;
static UnixSocketTable<UnixStreamSocket> stream_tbl;

std::pair<UnixStreamConnection, UnixStreamConnection> MakeStreamPair(
    UnixSocketAddr laddr, UnixSocketAddr raddr) {
  UnixStreamConnection local, remote;

  local.rx = std::make_shared<StreamPipe>(kStreamPipeSize);
  local.tx = std::make_shared<StreamPipe>(kStreamPipeSize);
  local.peer_name = std::move(raddr);

  remote.rx = local.tx;
  remote.tx = local.rx;
  remote.peer_name = std::move(laddr);

  return {std::move(local), std::move(remote)};
}

class UnixStreamSocket : public Socket {
 public:
  UnixStreamSocket(int flags = 0) noexcept
      : Socket(flags), state_(SocketState::kSockUnbound) {}

  UnixStreamSocket(UnixSocketAddr laddr, UnixStreamConnection conn,
                   int flags = 0) noexcept
      : Socket(flags),
        state_(SocketState::kSockConnected),
        local_name_(std::move(laddr)),
        v_(std::move(conn)) {
    Connection().rx->AttachReadPoll(&get_poll_source());
    Connection().tx->AttachWritePoll(&get_poll_source());
  }

  ~UnixStreamSocket() override {
    if (dent_)
      dent_->RemoveFromParent();
    else if (std::string &name = std::get<1>(local_name_); name.size())
      stream_tbl.Delete(name);
    if (state_ == SocketState::kSockConnected) {
      Connection().rx->CloseReader(&get_poll_source());
      Connection().tx->CloseWriter(&get_poll_source());
    } else if (state_ == SocketState::kSockListening) {
      for (UnixStreamConnection &c : Listener().accept_q) {
        c.rx->CloseReader();
        c.tx->CloseWriter();
      }
    }
  }

  Status<void> Bind(const SockAddrPtr addr) override {
    if (unlikely(state_ != SocketState::kSockUnbound)) return MakeError(EINVAL);

    Status<UnixSocketAddr> a = addr.ToUnixAddr();
    if (unlikely(!a)) return MakeError(a);
    auto &[type, name] = *a;
    std::shared_ptr<UnixSocketInode<UnixStreamSocket>> ino;
    if (type == UnixSocketAddressType::Pathname)
      ino = std::make_shared<UnixSocketInode<UnixStreamSocket>>(weak_this());

    if (type == UnixSocketAddressType::Pathname) {
      Status<std::shared_ptr<DirectoryEntry>> ret =
          InsertTo(myproc().get_fs(), name, std::move(ino));
      if (!ret) return MakeError(ret);
      dent_ = std::move(*ret);
    } else {
      Status<void> ret = stream_tbl.Insert(name, weak_this());
      if (!ret) return MakeError(ret);
    }
    local_name_ = std::move(*a);
    state_ = SocketState::kSockBound;
    return {};
  }

  Status<void> Listen(int backlog) override {
    if (state_ == SocketState::kSockConnected) return MakeError(EISCONN);
    if (unlikely(!has_name())) {
      Status<UnixSocketAddr> addr = stream_tbl.NameAndInsert(weak_this());
      if (!addr) return MakeError(addr);
      local_name_ = std::move(*addr);
    }
    rt::SpinGuard g(lock_);
    v_.emplace<UnixStreamListener>(backlog);
    state_ = SocketState::kSockListening;
    return {};
  }

  Status<void> Connect(const SockAddrPtr addr) override {
    // Do as much as possible before acquiring locks.
    if (unlikely(state_ == SocketState::kSockListening))
      return MakeError(EINVAL);

    // Parse address.
    Status<UnixSocketAddr> a = addr.ToUnixAddr();
    if (unlikely(!a)) return MakeError(a);

    // Locate server.
    Status<std::shared_ptr<UnixStreamSocket>> tmp =
        GetPeer<UnixStreamSocket>(*a, stream_tbl);
    if (!tmp) return MakeError(tmp);
    std::shared_ptr<UnixStreamSocket> &peer = *tmp;

    // Generate a name for this side of the connection, if needed.
    if (!has_name()) {
      Status<UnixSocketAddr> addr = stream_tbl.NameAndInsert(weak_this());
      if (!addr) return MakeError(addr);
      local_name_ = std::move(*addr);
    }

    // Create a pair of pipes for this connection.
    auto [local, remote] = MakeStreamPair(local_name_, *a);

    // Enqueue connection to the listener.
    Status<void> ret = peer->EnqueueConnection(std::move(remote));
    if (unlikely(!ret)) return ret;

    // Attach this side of the connection locally.
    v_.emplace<UnixStreamConnection>(std::move(local));
    Connection().rx->AttachReadPoll(&get_poll_source());
    Connection().tx->AttachWritePoll(&get_poll_source());
    state_ = SocketState::kSockConnected;
    return {};
  }

  Status<std::shared_ptr<Socket>> Accept(SockAddrPtr addr, int flags) override {
    if (unlikely(state_ != SocketState::kSockListening))
      return MakeError(EINVAL);

    UnixStreamListener &l = Listener();

    rt::SpinGuard g(lock_);
    if (!is_nonblocking()) {
      if (!rt::WaitInterruptible(lock_, l.waiter,
                                 [&] { return l.accept_q.size() > 0; }))
        return MakeError(ERESTARTSYS);
    } else {
      if (!l.accept_q.size()) return MakeError(EAGAIN);
    }

    UnixStreamConnection &peer = l.accept_q.front();
    if (addr) addr.FromUnixAddr(peer.peer_name);
    auto ret =
        std::make_shared<UnixStreamSocket>(local_name_, std::move(peer), flags);
    l.accept_q.pop_front();
    if (!l.accept_q.size()) get_poll_source().Clear(kPollIn);
    return std::move(ret);
  }

  Status<void> Shutdown(int how) override {
    if (state_ == SocketState::kSockListening) {
      Listener().shutdown = true;
      get_poll_source().Set(POLLRDHUP | POLLHUP | POLLIN);
      return {};
    }

    if (state_ != SocketState::kSockConnected) return MakeError(ENOTCONN);

    switch (how) {
      case SHUT_RD:
        Connection().rx->CloseReader();
        break;
      case SHUT_WR:
        Connection().tx->CloseWriter();
        break;
      case SHUT_RDWR:
        Connection().rx->CloseReader();
        Connection().tx->CloseWriter();
        break;
      default:
        return MakeError(EINVAL);
    }
    return {};
  }

  Status<void> RemoteAddr(SockAddrPtr ptr) const override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(ENOTCONN);
    if (unlikely(!ptr)) return MakeError(EINVAL);
    ptr.FromUnixAddr(Connection().peer_name);
    return {};
  }

  Status<void> LocalAddr(SockAddrPtr ptr) const override {
    if (unlikely(!ptr)) return MakeError(EINVAL);
    if (state_ == SocketState::kSockUnbound) {
      assert(!has_name());
      return MakeError(ENOTCONN);
    }
    ptr.FromUnixAddr(local_name_);
    return {};
  }

  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off = nullptr) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    return Connection().rx->Read(buf, is_nonblocking());
  }

  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off = nullptr) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    return Connection().tx->Write(buf, is_nonblocking());
  }

  Status<size_t> ReadFrom(std::span<std::byte> buf, SockAddrPtr raddr,
                          bool peek, bool nonblocking) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) raddr.FromUnixAddr(Connection().peer_name);
    nonblocking |= is_nonblocking();
    return Connection().rx->Read(buf, nonblocking, peek);
  }

  Status<size_t> WriteTo(std::span<const std::byte> buf,
                         const SockAddrPtr raddr, bool nonblocking) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) return MakeError(EISCONN);
    nonblocking |= is_nonblocking();
    return Connection().tx->Write(buf, nonblocking);
  }

  Status<size_t> WritevTo(std::span<const iovec> iov, const SockAddrPtr raddr,
                          bool nonblocking) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) return MakeError(EISCONN);
    nonblocking |= is_nonblocking();
    return Connection().tx->Writev(iov, nonblocking);
  }

  Status<size_t> Writev(std::span<const iovec> iov,
                        [[maybe_unused]] off_t *off = nullptr) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    return Connection().tx->Writev(iov, is_nonblocking());
  }

  Status<size_t> ReadvFrom(std::span<iovec> iov, SockAddrPtr raddr, bool peek,
                           bool nonblocking) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) raddr.FromUnixAddr(Connection().peer_name);
    nonblocking |= is_nonblocking();
    return Connection().rx->Readv(iov, nonblocking, peek);
  }

  Status<size_t> Readv(std::span<iovec> iov,
                       [[maybe_unused]] off_t *off) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    return Connection().rx->Readv(iov, is_nonblocking(), false);
  }

  Status<int> GetSockOpt(int level, int optname) const override {
    if (level != SOL_SOCKET) return MakeError(EINVAL);
    switch (optname) {
      case SO_ACCEPTCONN:
        return state_ == SocketState::kSockListening ? 1 : 0;
      case SO_DOMAIN:
        return AF_UNIX;
      case SO_PROTOCOL:
        return 0;
      case SO_TYPE:
        return SOCK_STREAM;
      case SO_ERROR:
        return 0;
      default:
        return MakeError(EINVAL);
    }
  }

  [[nodiscard]] UnixStreamListener &Listener() {
    return std::get<UnixStreamListener>(v_);
  }
  [[nodiscard]] UnixStreamConnection &Connection() {
    return std::get<UnixStreamConnection>(v_);
  }
  [[nodiscard]] const UnixStreamListener &Listener() const {
    return std::get<UnixStreamListener>(v_);
  }
  [[nodiscard]] const UnixStreamConnection &Connection() const {
    return std::get<UnixStreamConnection>(v_);
  }

  template <class Archive>
  void save(Archive &ar) const {
    ar(state_, local_name_, v_, dent_, cereal::base_class<Socket>(this));
  }

  template <class Archive>
  static void load_and_construct(
      Archive &ar, cereal::construct<UnixStreamSocket> &construct) {
    construct();
    UnixStreamSocket &sock = *construct.ptr();
    ar(sock.state_, sock.local_name_, sock.v_, sock.dent_,
       cereal::base_class<Socket>(construct.ptr()));
  }

 private:
  [[nodiscard]] std::weak_ptr<UnixStreamSocket> weak_this() {
    return std::static_pointer_cast<UnixStreamSocket>(shared_from_this());
  }

  // Add a waiting connection to the listening queue.
  Status<void> EnqueueConnection(UnixStreamConnection conn) {
    rt::SpinGuard g(lock_);
    if (unlikely(state_ != SocketState::kSockListening))
      return MakeError(ECONNREFUSED);

    UnixStreamListener &l = Listener();
    if (l.shutdown || l.accept_q.size() >= static_cast<size_t>(l.backlog))
      return MakeError(ECONNREFUSED);

    if (!l.accept_q.size()) get_poll_source().Set(kPollIn);
    l.accept_q.emplace_back(std::move(conn));
    l.waiter.Wake();
    return {};
  }

  [[nodiscard]] bool has_name() const {
    return std::get<1>(local_name_).size() > 0;
  }

  rt::Spin lock_;
  SocketState state_;
  UnixSocketAddr local_name_;
  std::variant<UnixStreamConnection, UnixStreamListener> v_;
  std::shared_ptr<DirectoryEntry> dent_;
};

std::pair<int, int> CreatePipeSocket(int flags, bool datagram) {
  std::shared_ptr<File> pipe1, pipe2;

  if (datagram) {
    auto f1 = std::make_shared<UnixDatagramSocket>(flags);
    auto f2 = std::make_shared<UnixDatagramSocket>(flags);

    f1->SetLocalName();
    f1->remote_ = f2;
    f1->connected_ = true;

    f2->SetLocalName();
    f2->remote_ = f1;
    f2->connected_ = true;

    pipe1 = std::move(f1);
    pipe2 = std::move(f2);
  } else {
    // Create two sides of the connection without names.
    auto [conn1, conn2] = MakeStreamPair(UnixSocketAddr{}, UnixSocketAddr{});
    pipe1 = std::make_shared<UnixStreamSocket>(UnixSocketAddr{},
                                               std::move(conn1), flags);
    pipe2 = std::make_shared<UnixStreamSocket>(UnixSocketAddr{},
                                               std::move(conn2), flags);
  }

  // Insert both files into the file table.
  FileTable &ftbl = myproc().get_file_table();
  bool cloexec = (flags & kFlagCloseExec) > 0;
  int fd1 = ftbl.Insert(std::move(pipe1), cloexec);
  int fd2 = ftbl.Insert(std::move(pipe2), cloexec);
  return std::make_pair(fd1, fd2);
}

Status<std::shared_ptr<Socket>> CreateUnixSocket(int type, int protocol,
                                                 int flags) {
  if (protocol != 0) return MakeError(EPROTONOSUPPORT);
  if (type == SOCK_DGRAM) return std::make_shared<UnixDatagramSocket>(flags);
  if (type == SOCK_STREAM) return std::make_shared<UnixStreamSocket>(flags);
  // TODO: seqpacket.
  return MakeError(EINVAL);
}

long usys_socketpair(int domain, int type, int protocol, int sv[2]) {
  if (domain != AF_UNIX || protocol != 0) return -EAFNOSUPPORT;
  bool datagram = (type & kSockTypeMask) == SOCK_DGRAM;
  if (!datagram && (type & kSockTypeMask) != SOCK_STREAM) return -EINVAL;
  auto [fd1, fd2] = CreatePipeSocket(type & ~kSockTypeMask, datagram);
  sv[0] = fd1;
  sv[1] = fd2;
  return 0;
}

template <class Archive>
void SerializeUnixSocketState(Archive &ar) {
  ar(dgram_tbl, stream_tbl);
}

using cereal::BinaryInputArchive;
using cereal::BinaryOutputArchive;

template void SerializeUnixSocketState<BinaryOutputArchive>(
    BinaryOutputArchive &ar);
template void SerializeUnixSocketState<BinaryInputArchive>(
    BinaryInputArchive &ar);

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::UnixDatagramSocket);
CEREAL_REGISTER_TYPE(junction::UnixStreamSocket);
CEREAL_REGISTER_TYPE(junction::UnixSocketInode<junction::UnixDatagramSocket>);
CEREAL_REGISTER_TYPE(junction::UnixSocketInode<junction::UnixStreamSocket>);
