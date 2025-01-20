// pipe.cc - support for UNIX pipes
//
// TODO(amb): Support the "packet mode" enabled by O_DIRECT?

#include "junction/fs/pipe.h"

#include <atomic>
#include <memory>

#include "junction/base/byte_channel.h"
#include "junction/base/message_channel.h"
#include "junction/fs/file.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/limits.h"
#include "junction/snapshot/cereal.h"

namespace junction {

namespace {

using StreamPipe = WaitableChannel<ByteChannel, false>;
using MsgPipe = WaitableChannel<MessageChannel<void>, false>;

template <class Pipe>
class PipeReaderFile : public File {
 public:
  PipeReaderFile(std::shared_ptr<Pipe> pipe, int flags) noexcept
      : File(FileType::kNormal, flags & kFlagNonblock, FileMode::kRead),
        pipe_(std::move(pipe)) {
    pipe_->AttachReadPoll(&get_poll_source());
  }
  ~PipeReaderFile() override { pipe_->CloseReader(&get_poll_source()); }

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

template <class Pipe>
class PipeWriterFile : public File {
 public:
  PipeWriterFile(std::shared_ptr<Pipe> pipe, int flags) noexcept
      : File(FileType::kNormal, flags & kFlagNonblock, FileMode::kWrite),
        pipe_(std::move(pipe)) {
    pipe_->AttachWritePoll(&get_poll_source());
  }
  ~PipeWriterFile() override { pipe_->CloseWriter(&get_poll_source()); }

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
  std::shared_ptr<File> reader, writer;

  if (flags & kFlagDirect) {
    // Create the pipe (shared between the reader and writer file).
    auto pipe = std::make_shared<MsgPipe>(kPipeSize);

    // Create the reader file.
    reader = std::make_shared<PipeReaderFile<MsgPipe>>(pipe, flags);

    // Create the writer file.
    writer = std::make_shared<PipeWriterFile<MsgPipe>>(std::move(pipe), flags);
  } else {
    // Create the pipe (shared between the reader and writer file).
    auto pipe = std::make_shared<StreamPipe>(kPipeSize);

    // Create the reader file.
    reader = std::make_shared<PipeReaderFile<StreamPipe>>(pipe, flags);

    // Create the writer file.
    writer =
        std::make_shared<PipeWriterFile<StreamPipe>>(std::move(pipe), flags);
  }

  // Insert both files into the file table.
  FileTable &ftbl = myproc().get_file_table();
  bool cloexec = (flags & kFlagCloseExec) > 0;
  int read_fd = ftbl.Insert(std::move(reader), cloexec);
  int write_fd = ftbl.Insert(std::move(writer), cloexec);
  return std::make_pair(read_fd, write_fd);
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
  if ((flags & ~(kFlagNonblock | kFlagCloseExec | kFlagDirect)) != 0)
    return -EINVAL;
  auto [read_fd, write_fd] = CreatePipe(flags);
  pipefd[0] = read_fd;
  pipefd[1] = write_fd;
  return 0;
}

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::PipeReaderFile<junction::StreamPipe>);
CEREAL_REGISTER_TYPE(junction::PipeWriterFile<junction::StreamPipe>);
CEREAL_REGISTER_TYPE(junction::PipeReaderFile<junction::MsgPipe>);
CEREAL_REGISTER_TYPE(junction::PipeWriterFile<junction::MsgPipe>);
