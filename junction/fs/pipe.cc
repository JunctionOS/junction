// pipe.cc - support for UNIX pipes
//
// TODO(amb): Support the "packet mode" enabled by O_DIRECT?

extern "C" {
#include <net/ip.h>
#include <sys/socket.h>
}

#include <atomic>
#include <memory>

#include "junction/base/byte_channel.h"
#include "junction/fs/file.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/limits.h"
#include "junction/net/socket.h"
#include "junction/snapshot/cereal.h"

namespace junction {

namespace {

class Pipe {
 public:
  friend class PipeReaderFile;
  friend class PipeWriterFile;
  friend class PipeSocketFile;

  explicit Pipe(size_t size) noexcept : chan_(size) {}
  ~Pipe() = default;

  Status<size_t> Read(std::span<std::byte> buf, bool nonblocking,
                      bool peek = false);
  Status<size_t> Write(std::span<const std::byte> buf, bool nonblocking);
  void CloseReader();
  void CloseWriter();

  void AttachReadPoll(PollSource *p) {
    assert(!read_poll_);
    read_poll_ = p;
    if (reader_is_closed()) return;
    if (writer_is_closed())
      read_poll_->Set(kPollHUp);
    else if (!is_empty())
      read_poll_->Set(kPollIn);
  }

  void AttachWritePoll(PollSource *p) {
    assert(!write_poll_);
    write_poll_ = p;
    if (writer_is_closed()) return;
    if (reader_is_closed())
      write_poll_->Set(kPollErr);
    else if (!is_full())
      write_poll_->Set(kPollOut);
  }

  template <class Archive>
  void save(Archive &ar) const {
    ar(chan_.get_size(), chan_, reader_closed_, writer_closed_);
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<Pipe> &construct) {
    size_t sz;
    ar(sz);
    construct(sz);

    Pipe &p = *construct.ptr();
    ar(p.chan_, p.reader_closed_, p.writer_closed_);
  }

  [[nodiscard]] bool is_empty() const { return chan_.is_empty(); }
  [[nodiscard]] bool is_full() const { return chan_.is_full(); }

 private:
  bool reader_is_closed() const {
    return reader_closed_.load(std::memory_order_acquire);
  }
  bool writer_is_closed() const {
    return writer_closed_.load(std::memory_order_acquire);
  }

  rt::Spin lock_;
  ByteChannel chan_;
  std::atomic<bool> reader_closed_{false};
  std::atomic<bool> writer_closed_{false};
  rt::ThreadWaker read_waker_;
  rt::ThreadWaker write_waker_;
  PollSource *read_poll_{nullptr};
  PollSource *write_poll_{nullptr};
};

Status<size_t> Pipe::Read(std::span<std::byte> buf, bool nonblocking,
                          bool peek) {
  size_t n;
  while (true) {
    // Read from the channel (without locking).
    Status<size_t> ret = chan_.Read(buf, peek);
    if (ret) {
      n = *ret;
      break;
    }

    // Return if can't block.
    if (nonblocking) {
      if (writer_is_closed() && chan_.is_empty()) return 0;
      return MakeError(EAGAIN);
    }

    // Channel is empty, block and wait.
    assert(ret.error() == EAGAIN);
    rt::SpinGuard guard(lock_);
    bool signaled = !rt::WaitInterruptible(lock_, read_waker_, [this] {
      return !chan_.is_empty() || writer_is_closed();
    });
    if (writer_is_closed() && chan_.is_empty()) return 0;
    if (signaled) return MakeError(EINTR);
  }

  // Wake the writer and any pollers.
  {
    rt::SpinGuard guard(lock_);
    if (chan_.is_empty()) read_poll_->Clear(kPollIn);
    if (writer_is_closed()) return n;
    if (!chan_.is_full()) {
      write_poll_->Set(kPollOut);
      write_waker_.Wake();
    }
  }
  return n;
}

Status<size_t> Pipe::Write(std::span<const std::byte> buf, bool nonblocking) {
  size_t n;
  while (true) {
    // Write to the channel (without locking).
    Status<size_t> ret = chan_.Write(buf);
    if (ret) {
      n = *ret;
      break;
    }

    // Return if can't block.
    if (nonblocking) {
      if (reader_is_closed()) return MakeError(EPIPE);
      return MakeError(EAGAIN);
    }

    // Channel is full, block and wait.
    assert(ret.error() == EAGAIN);
    rt::SpinGuard guard(lock_);
    bool signaled = !rt::WaitInterruptible(lock_, write_waker_, [this] {
      return !chan_.is_full() || reader_is_closed();
    });
    if (reader_is_closed()) return MakeError(EPIPE);
    if (signaled) return MakeError(EINTR);
  }

  // Wake the reader and any pollers.
  {
    rt::SpinGuard guard(lock_);
    if (chan_.is_full()) write_poll_->Clear(kPollOut);
    if (reader_is_closed()) return MakeError(EPIPE);
    if (!chan_.is_empty()) {
      read_poll_->Set(kPollIn);
      read_waker_.Wake();
    }
  }
  return n;
}

void Pipe::CloseReader() {
  rt::SpinGuard guard(lock_);
  reader_closed_.store(true, std::memory_order_release);
  if (!writer_is_closed()) {
    write_poll_->Set(kPollErr);  // POSIX requires this for pipe, not kPollRdHUp
    write_waker_.Wake();
  }
}

void Pipe::CloseWriter() {
  rt::SpinGuard guard(lock_);
  writer_closed_.store(true, std::memory_order_release);
  if (!reader_is_closed()) {
    read_poll_->Set(kPollHUp);
    read_waker_.Wake();
  }
}

class PipeReaderFile : public File {
 public:
  PipeReaderFile(std::shared_ptr<Pipe> pipe, int flags) noexcept
      : File(FileType::kNormal, flags & kFlagNonblock, FileMode::kRead),
        pipe_(std::move(pipe)) {
    pipe_->AttachReadPoll(&get_poll_source());
  }
  ~PipeReaderFile() override { pipe_->CloseReader(); }

  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off) override {
    return pipe_->Read(buf, is_nonblocking());
  }

  Status<void> Stat(struct stat *statbuf) const override {
    // TODO(jf): do we need to fill in more fields?
    memset(statbuf, 0, sizeof(*statbuf));
    statbuf->st_mode = S_IFIFO | S_IRUSR | S_IWUSR;
    return {};
  }

 private:
  friend class cereal::access;

  template <class Archive>
  void save(Archive &ar) const {
    ar(pipe_, cereal::base_class<File>(this));
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<PipeReaderFile> &construct) {
    std::shared_ptr<Pipe> pipe;
    ar(pipe);
    construct(std::move(pipe), 0);
    ar(cereal::base_class<File>(construct.ptr()));
  }

  std::shared_ptr<Pipe> pipe_;
};

class PipeWriterFile : public File {
 public:
  PipeWriterFile(std::shared_ptr<Pipe> pipe, int flags) noexcept
      : File(FileType::kNormal, flags & kFlagNonblock, FileMode::kWrite),
        pipe_(std::move(pipe)) {
    pipe_->AttachWritePoll(&get_poll_source());
  }
  ~PipeWriterFile() override { pipe_->CloseWriter(); }

  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off) override {
    return pipe_->Write(buf, is_nonblocking());
  }

  Status<void> Stat(struct stat *statbuf) const override {
    memset(statbuf, 0, sizeof(*statbuf));
    statbuf->st_mode = S_IFIFO | S_IWUSR | S_IRUSR;
    return {};
  }

 private:
  friend class cereal::access;

  template <class Archive>
  void save(Archive &ar) const {
    ar(pipe_, cereal::base_class<File>(this));
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<PipeWriterFile> &construct) {
    std::shared_ptr<Pipe> pipe;
    ar(pipe);
    construct(std::move(pipe), 0);
    ar(cereal::base_class<File>(construct.ptr()));
  }

  std::shared_ptr<Pipe> pipe_;
};

std::pair<int, int> CreatePipe(int flags = 0) {
  // Create the pipe (shared between the reader and writer file).
  auto pipe = std::make_shared<Pipe>(kPipeSize);

  // Create the reader file.
  auto reader = std::make_shared<PipeReaderFile>(pipe, flags);

  // Create the writer file.
  auto writer = std::make_shared<PipeWriterFile>(std::move(pipe), flags);

  // Insert both files into the file table.
  FileTable &ftbl = myproc().get_file_table();
  bool cloexec = (flags & kFlagCloseExec) > 0;
  int read_fd = ftbl.Insert(std::move(reader), cloexec);
  int write_fd = ftbl.Insert(std::move(writer), cloexec);
  return std::make_pair(read_fd, write_fd);
}

class PipeSocketFile : public Socket {
 public:
  PipeSocketFile(std::shared_ptr<Pipe> rx, std::shared_ptr<Pipe> tx,
                 int flags = 0)
      : Socket(flags), rx_(std::move(rx)), tx_(std::move(tx)) {
    rx_->AttachReadPoll(&get_poll_source());
    tx_->AttachWritePoll(&get_poll_source());
  }
  ~PipeSocketFile() override {
    rx_->CloseReader();
    tx_->CloseWriter();
  }

  Status<void> Shutdown(int how) override {
    switch (how) {
      case SHUT_RD:
        rx_->CloseReader();
        break;
      case SHUT_WR:
        tx_->CloseWriter();
        break;
      case SHUT_RDWR:
        rx_->CloseReader();
        tx_->CloseWriter();
        break;
      default:
        return MakeError(EINVAL);
    }
    return {};
  }

  Status<size_t> ReadFrom(std::span<std::byte> buf, SockAddrPtr raddr,
                          bool peek, bool nonblocking) override {
    if (raddr) raddr.FromNetAddr({MAKE_IP_ADDR(127, 0, 0, 1), 0});
    return rx_->Read(buf, is_nonblocking() || nonblocking, peek);
  }

  Status<size_t> WriteTo(std::span<const std::byte> buf,
                         const SockAddrPtr raddr, bool nonblocking) override {
    return tx_->Write(buf, is_nonblocking() || nonblocking);
  }

  Status<size_t> WritevTo(std::span<const iovec> iov, const SockAddrPtr raddr,
                          bool nonblocking) override {
    ssize_t total_bytes = 0;
    Status<size_t> ret;
    for (auto &v : iov) {
      if (!v.iov_len) continue;
      ret = WriteTo(
          writable_span(reinterpret_cast<const char *>(v.iov_base), v.iov_len),
          raddr, nonblocking);
      if (!ret) break;
      total_bytes += *ret;
      if (*ret < v.iov_len) break;
    }
    if (total_bytes) return total_bytes;
    return ret;
  }

  Status<size_t> Write(std::span<const std::byte> buf, off_t *off) override {
    return tx_->Write(buf, is_nonblocking());
  }

 private:
  friend cereal::access;
  template <class Archive>
  void save(Archive &ar) const {
    ar(rx_, tx_, cereal::base_class<Socket>(this));
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<PipeSocketFile> &construct) {
    std::shared_ptr<Pipe> rx;
    std::shared_ptr<Pipe> tx;
    ar(rx, tx);
    construct(std::move(rx), std::move(tx), 0);
    ar(cereal::base_class<Socket>(construct.ptr()));
  }

  std::shared_ptr<Pipe> rx_;
  std::shared_ptr<Pipe> tx_;
};

std::pair<int, int> CreatePipeSocket(int flags = 0) {
  auto p1 = std::make_shared<Pipe>(kPipeSize);
  auto p2 = std::make_shared<Pipe>(kPipeSize);

  // Create the reader file.
  auto pipe1 = std::make_shared<PipeSocketFile>(p1, p2, flags);
  auto pipe2 =
      std::make_shared<PipeSocketFile>(std::move(p2), std::move(p1), flags);

  // Insert both files into the file table.
  FileTable &ftbl = myproc().get_file_table();
  bool cloexec = (flags & kFlagCloseExec) > 0;
  int fd1 = ftbl.Insert(std::move(pipe1), cloexec);
  int fd2 = ftbl.Insert(std::move(pipe2), cloexec);
  return std::make_pair(fd1, fd2);
}

}  // namespace

long usys_pipe(int pipefd[2]) {
  auto [read_fd, write_fd] = CreatePipe();
  pipefd[0] = read_fd;
  pipefd[1] = write_fd;
  return 0;
}

long usys_pipe2(int pipefd[2], int flags) {
  // check for supported flags.
  if ((flags & ~(kFlagNonblock | kFlagCloseExec)) != 0) return -EINVAL;
  auto [read_fd, write_fd] = CreatePipe(flags);
  pipefd[0] = read_fd;
  pipefd[1] = write_fd;
  return 0;
}

long usys_socketpair(int domain, int type, [[maybe_unused]] int protocol,
                     int sv[2]) {
  if (domain != AF_UNIX) return -EAFNOSUPPORT;
  if ((type & kSockTypeMask) != SOCK_STREAM) return -EINVAL;
  auto [fd1, fd2] = CreatePipeSocket(type & ~kSockTypeMask);
  sv[0] = fd1;
  sv[1] = fd2;
  return 0;
}

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::PipeReaderFile);
CEREAL_REGISTER_TYPE(junction::PipeWriterFile);
CEREAL_REGISTER_TYPE(junction::PipeSocketFile);