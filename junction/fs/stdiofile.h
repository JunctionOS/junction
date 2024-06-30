// stdiofile.h - support for STDIN, STDOUT, STDERR

#pragma once

#include <span>
#include <string_view>

#include "junction/base/error.h"
#include "junction/fs/file.h"
#include "junction/snapshot/cereal.h"

namespace junction {

constexpr int kStdInFileNo = STDIN_FILENO;
constexpr int kStdOutFileNo = STDOUT_FILENO;
constexpr int kStdErrFileNo = STDERR_FILENO;

class StdIOFile : public File {
 public:
  StdIOFile(int fd, FileMode mode);
  Status<size_t> Read(std::span<std::byte> buf, off_t *off) override;
  Status<size_t> Write(std::span<const std::byte> buf, off_t *off) override;
  Status<void> Stat(struct stat *statbuf) const override;
  Status<void> Sync() override;

  [[nodiscard]] int get_fd() const { return fd_; }

 private:
  friend class cereal::access;

  template <class Archive>
  void save(Archive &ar) const {
    ar(fd_, get_mode(), cereal::base_class<File>(this));
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<StdIOFile> &construct) {
    int fd;
    FileMode mode;
    ar(fd, mode);
    construct(fd, mode);

    ar(cereal::base_class<File>(construct.ptr()));
  }

  int fd_;
};

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::StdIOFile);
