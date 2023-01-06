// pipe.cc - support for UNIX pipes
//
// TODO(amb): Support the "packet mode" enabled by O_DIRECT?

#include <atomic>
#include <memory>

#include "junction/base/arch.h"
#include "junction/base/byte_channel.h"
#include "junction/kernel/file.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

namespace {

// The size in bytes of the pipe's channel.
constexpr size_t kPipeSize = 16 * kPageSize;  // same default as Linux

class Pipe {
 public:
  explicit Pipe(size_t size) noexcept : chan_(size) {}
  ~Pipe() = default;

  Status<size_t> Read(std::span<std::byte> buf, bool nonblocking);
  Status<size_t> Write(std::span<const std::byte> buf, bool nonblocking);
  void CloseReader();
  void CloseWriter();

 private:
  bool reader_is_closed() const {
    return reader_closed_.load(std::memory_order_acquire);
  }
  bool writer_is_closed() const {
    return writer_closed_.load(std::memory_order_acquire);
  }

  rt::Spin lock_;
  std::atomic<bool> reader_closed_{false};
  std::atomic<bool> writer_closed_{false};
  rt::ThreadWaker read_waker_;
  rt::ThreadWaker write_waker_;
  ByteChannel chan_;
};

Status<size_t> Pipe::Read(std::span<std::byte> buf, bool nonblocking) {
  size_t n;
  while (true) {
    // Read from the channel (without locking).
    Status<size_t> ret = chan_.Read(buf);
    if (ret) {
      n = *ret;
      break;
    }

    // Return if can't block.
    if (nonblocking) {
      if (writer_is_closed()) return 0;
      return MakeError(EAGAIN);
    }

    // Channel is empty, block and wait.
    assert(ret.error() == EAGAIN);
    rt::SpinGuard guard(lock_);
    guard.Park(read_waker_,
               [this] { return !chan_.is_empty() || writer_is_closed(); });
    if (writer_is_closed()) return 0;
  }

  // Wake the writer if it's blocked on a full channel.
  {
    rt::SpinGuard guard(lock_);
    write_waker_.Wake();
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
    guard.Park(write_waker_,
               [this] { return !chan_.is_full() || reader_is_closed(); });
    if (reader_is_closed()) return MakeError(EPIPE);
  }

  // Wake the reader if it's blocked on an empty channel.
  {
    rt::SpinGuard guard(lock_);
    if (reader_is_closed()) return MakeError(EPIPE);
    read_waker_.Wake();
  }
  return n;
}

void Pipe::CloseReader() {
  rt::SpinGuard guard(lock_);
  reader_closed_.store(true, std::memory_order_release);
  write_waker_.Wake();
}

void Pipe::CloseWriter() {
  rt::SpinGuard guard(lock_);
  writer_closed_.store(true, std::memory_order_release);
  read_waker_.Wake();
}

class PipeReaderFile : public File {
 public:
  PipeReaderFile(std::shared_ptr<Pipe> pipe, int flags) noexcept
      : File(FileType::kNormal, flags & kFlagNonblock, kModeRead),
        pipe_(std::move(pipe)) {}
  ~PipeReaderFile() override { pipe_->CloseReader(); }

  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off) override {
    return pipe_->Read(buf, (get_flags() & kFlagNonblock) != 0);
  }

 private:
  std::shared_ptr<Pipe> pipe_;
};

class PipeWriterFile : public File {
 public:
  PipeWriterFile(std::shared_ptr<Pipe> pipe, int flags) noexcept
      : File(FileType::kNormal, flags & kFlagNonblock, kModeWrite),
        pipe_(std::move(pipe)) {}
  ~PipeWriterFile() override { pipe_->CloseWriter(); }

  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off) override {
    return pipe_->Write(buf, (get_flags() & kFlagNonblock) != 0);
  }

 private:
  std::shared_ptr<Pipe> pipe_;
};

std::tuple<int, int> CreatePipe(int flags = 0) {
  auto pipe = std::make_shared<Pipe>(kPipeSize);
  FileTable &ftbl = myproc().get_file_table();
  int read_fd = ftbl.Insert(std::make_shared<PipeReaderFile>(pipe, flags));
  int write_fd =
      ftbl.Insert(std::make_shared<PipeWriterFile>(std::move(pipe), flags));
  return std::make_tuple(read_fd, write_fd);
}

}  // namespace

int usys_pipe(int pipefd[2]) {
  auto [read_fd, write_fd] = CreatePipe();
  pipefd[0] = read_fd;
  pipefd[1] = write_fd;
  return 0;
}

int usys_pipe2(int pipefd[2], int flags) {
  // check for supported flags.
  if ((flags & ~kFlagNonblock) != 0) return -EINVAL;
  auto [read_fd, write_fd] = CreatePipe(flags);
  pipefd[0] = read_fd;
  pipefd[1] = write_fd;
  return 0;
}

}  // namespace junction
