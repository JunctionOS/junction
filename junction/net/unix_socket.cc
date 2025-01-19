
#include <variant>

#include "junction/fs/pipe.h"
#include "junction/kernel/proc.h"
#include "junction/net/socket.h"

namespace junction {

class UnixStreamSocket;

struct UnixStreamConnection {
  UnixSocketAddr peer_name;
  std::shared_ptr<StreamPipe> rx;
  std::shared_ptr<StreamPipe> tx;
};

struct UnixStreamListener {
  UnixStreamListener(int backlog) : backlog(backlog) {}
  int backlog;
  bool shutdown{false};
  std::list<UnixStreamConnection> accept_q;
  rt::ThreadWaker waiter;
};

class UnixSocketInode : public Inode {
 public:
  UnixSocketInode(std::weak_ptr<UnixStreamSocket> sock)
      : Inode(kTypeSocket | 0600, AllocateInodeNumber()),
        sock_(std::move(sock)) {}

  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    return {};
  }

  //  bool SnapshotPrunable() override { return true; }

  // Open a file for this inode.
  Status<std::shared_ptr<File>> Open(
      uint32_t flags, FileMode mode,
      std::shared_ptr<DirectoryEntry> dent) override {
    return MakeError(EINVAL);
  }

  std::weak_ptr<UnixStreamSocket> get_sock() { return sock_; }

 private:
  std::weak_ptr<UnixStreamSocket> sock_;
};

class UnixAbstractSocketTable {
 public:
  Status<void> Insert(std::string_view name,
                      std::weak_ptr<UnixStreamSocket> ino) {
    rt::SpinGuard g(lock_);
    std::weak_ptr<UnixStreamSocket> &mp = tbl_[std::string(name)];
    if (!mp.expired()) return MakeError(EADDRINUSE);
    std::swap(mp, ino);
    return {};
  }

  std::weak_ptr<UnixStreamSocket> Find(std::string_view name) {
    rt::SpinGuard g(lock_);
    auto it = tbl_.find(name);
    if (it != tbl_.end()) return it->second;
    return {};
  }

  void Delete(std::string_view name) {
    rt::SpinGuard g(lock_);
    if (auto it = tbl_.find(name); it != tbl_.end()) tbl_.erase(it);
  }

 private:
  rt::Spin lock_;
  std::map<std::string, std::weak_ptr<UnixStreamSocket>, std::less<>> tbl_;
};

static UnixAbstractSocketTable unsock_tbl;

Status<std::shared_ptr<UnixStreamSocket>> GetPeer(UnixSocketAddr &addr) {
  auto &[type, name] = addr;
  std::shared_ptr<UnixStreamSocket> remote;
  if (type == UnixSocketAddressType::Pathname) {
    Status<std::shared_ptr<Inode>> ino = LookupInode(myproc().get_fs(), name);
    if (!ino) return MakeError(ECONNREFUSED);
    UnixSocketInode *uino = dynamic_cast<UnixSocketInode *>(ino->get());
    if (!uino) return MakeError(ECONNREFUSED);
    remote = uino->get_sock().lock();
  } else {
    remote = unsock_tbl.Find(name).lock();
  }
  if (!remote) return MakeError(ECONNREFUSED);
  return remote;
}

std::pair<UnixStreamConnection, UnixStreamConnection> MakeStreamPair(
    UnixSocketAddr laddr, UnixSocketAddr raddr) {
  UnixStreamConnection local, remote;

  local.rx = std::make_shared<StreamPipe>(4096);
  local.tx = std::make_shared<StreamPipe>(4096);
  local.peer_name = std::move(raddr);

  remote.rx = local.tx;
  remote.tx = local.rx;
  remote.peer_name = std::move(laddr);

  return {std::move(local), std::move(remote)};
}

// Represents a SOCK_STREAM Unix socket (created with socket()).
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
      unsock_tbl.Delete(name);
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
    std::shared_ptr<UnixSocketInode> ino;
    if (type == UnixSocketAddressType::Pathname)
      ino = std::make_shared<UnixSocketInode>(weak_this());

    if (type == UnixSocketAddressType::Pathname) {
      Status<std::shared_ptr<DirectoryEntry>> ret =
          InsertTo(myproc().get_fs(), name, std::move(ino));
      if (!ret) return MakeError(ret);
      dent_ = std::move(*ret);
    } else {
      Status<void> ret = unsock_tbl.Insert(name, weak_this());
      if (!ret) return MakeError(ret);
    }
    local_name_ = std::move(*a);
    state_ = SocketState::kSockBound;
    return {};
  }

  Status<void> Listen(int backlog) override {
    if (state_ == SocketState::kSockConnected) return MakeError(EISCONN);
    if (unlikely(!has_name())) BindRandomName();
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
    Status<std::shared_ptr<UnixStreamSocket>> tmp = GetPeer(*a);
    if (!tmp) return MakeError(tmp);
    std::shared_ptr<UnixStreamSocket> &peer = *tmp;

    // Generate a name for this side of the connection, if needed.
    if (!has_name()) BindRandomName();

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
    return Connection().rx->Read(buf, nonblocking, peek);
  }

  Status<size_t> WriteTo(std::span<const std::byte> buf,
                         const SockAddrPtr raddr, bool nonblocking) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) return MakeError(EISCONN);
    return Connection().tx->Write(buf, nonblocking);
  }

  Status<size_t> WritevTo(std::span<const iovec> iov, const SockAddrPtr raddr,
                          bool nonblocking) override {
    if (unlikely(state_ != SocketState::kSockConnected))
      return MakeError(EINVAL);
    if (raddr) return MakeError(EISCONN);
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

  void BindRandomName() {
    constexpr size_t kLength = 40;

    assert(!has_name());
    std::string out;
    out.resize(kLength);
    std::span<std::byte> b(reinterpret_cast<std::byte *>(out.data()), kLength);

    while (true) {
      if (!ReadRandom(b)) LOG(WARN) << "error getting random bytes";
      for (size_t i = 0; i < kLength; i++)
        out[i] = 'a' + static_cast<uint8_t>(out[i]) % 26;
      if (unsock_tbl.Insert(out, weak_this())) break;
    }
    local_name_ = {UnixSocketAddressType::Abstract, std::move(out)};
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

Status<std::shared_ptr<Socket>> CreateUnixSocket(int type, int protocol,
                                                 int flags) {
  if (type != SOCK_STREAM) return MakeError(EINVAL);
  if (protocol != 0) return MakeError(EPROTONOSUPPORT);
  return std::make_shared<UnixStreamSocket>(flags);
}

}  // namespace junction
