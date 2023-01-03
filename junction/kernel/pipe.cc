// pipe.cc - support for UNIX pipes
//
// TODO(amb): Support the "packet mode" enabled by O_DIRECT?

#include <memory>

#include "junction/base/arch.h"
#include "junction/base/byte_channel.h"
#include "junction/kernel/file.h"
#include "junction/kernel/proc.h"

namespace junction {

namespace {

// The size in bytes of the pipe's channel.
constexpr size_t kPipeSize = 16 * kPageSize;  // same default as Linux

class Pipe {
 public:
  explicit Pipe(size_t size) noexcept : chan_(size) {}
  ~Pipe() = default;

  Status<size_t> Read(std::span<std::byte> buf);
  Status<size_t> Write(std::span<const std::byte> buf);
  void CloseReader();
  void CloseWriter();

 private:
  rt::Spin lock_;
  bool reader_closed_{false};
  bool writer_closed_{false};
  rt::ThreadWaker read_waker_;
  rt::ThreadWaker write_waker_;
  ByteChannel chan_;
};

Status<size_t> Pipe::Read(std::span<std::byte> buf) {
  size_t n;
  while (true) {
    // Read from the channel (without locking).
    Status<size_t> ret = chan_.Read(buf);
    if (ret) {
      n = *ret;
      break;
    }

    // Channel is empty, block and wait.
    assert(ret.error() == EAGAIN);
    rt::SpinGuard guard(lock_);
    guard.Park(read_waker_,
               [this] { return !chan_.is_empty() || writer_closed_; });
    if (writer_closed_) return 0;
  }

  // Wake the writer if it's blocked on a full channel.
  {
    rt::SpinGuard guard(lock_);
    write_waker_.Wake();
  }
  return n;
}

Status<size_t> Pipe::Write(std::span<const std::byte> buf) {
  size_t n;
  while (true) {
    // Write to the channel (without locking).
    Status<size_t> ret = chan_.Write(buf);
    if (ret) {
      n = *ret;
      break;
    }

    // Channel is full, block and wait.
    assert(ret.error() == EAGAIN);
    rt::SpinGuard guard(lock_);
    guard.Park(write_waker_,
               [this] { return !chan_.is_full() || reader_closed_; });
    if (reader_closed_) return MakeError(EPIPE);
  }

  // Wake the reader if it's blocked on an empty channel.
  {
    rt::SpinGuard guard(lock_);
    if (reader_closed_) return MakeError(EPIPE);
    read_waker_.Wake();
  }
  return n;
}

void Pipe::CloseReader() {
  rt::SpinGuard guard(lock_);
  reader_closed_ = true;
  write_waker_.Wake();
}

void Pipe::CloseWriter() {
  rt::SpinGuard guard(lock_);
  writer_closed_ = true;
  read_waker_.Wake();
}

class PipeReaderFile : public File {
 public:
  explicit PipeReaderFile(std::shared_ptr<Pipe> pipe)
      : File(FileType::kNormal, 0, kModeRead), pipe_(std::move(pipe)) {}
  ~PipeReaderFile() override { pipe_->CloseReader(); }

  Status<size_t> Read(std::span<std::byte> buf,
                      [[maybe_unused]] off_t *off) override {
    return pipe_->Read(buf);
  }

 private:
  std::shared_ptr<Pipe> pipe_;
};

class PipeWriterFile : public File {
 public:
  explicit PipeWriterFile(std::shared_ptr<Pipe> pipe)
      : File(FileType::kNormal, 0, kModeWrite), pipe_(std::move(pipe)) {}
  ~PipeWriterFile() override { pipe_->CloseWriter(); }

  Status<size_t> Write(std::span<const std::byte> buf,
                       [[maybe_unused]] off_t *off) override {
    return pipe_->Write(buf);
  }

 private:
  std::shared_ptr<Pipe> pipe_;
};

std::tuple<int, int> CreatePipe() {
  auto pipe = std::make_shared<Pipe>(kPipeSize);
  FileTable &ftbl = myproc().get_file_table();
  int read_fd = ftbl.Insert(std::make_shared<PipeReaderFile>(pipe));
  int write_fd = ftbl.Insert(std::make_shared<PipeWriterFile>(std::move(pipe)));
  return std::make_tuple(read_fd, write_fd);
}

}  // namespace

int usys_pipe(int pipefd[2]) {
  auto [read_fd, write_fd] = CreatePipe();
  pipefd[0] = read_fd;
  pipefd[1] = write_fd;
  return 0;
}

}  // namespace junction
