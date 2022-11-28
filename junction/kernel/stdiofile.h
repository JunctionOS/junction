// stdiofile.h - support for STDIN, STDOUT, STDERR

#pragma once

#include <span>
#include <string_view>

#include "junction/base/error.h"
#include "junction/kernel/file.h"

namespace junction {

constexpr int kStdInFileNo = STDIN_FILENO;
constexpr int kStdOutFileNo = STDOUT_FILENO;
constexpr int kStdErrFileNo = STDERR_FILENO;

class StdIOFile : public File {
 public:
  StdIOFile(int fd, unsigned int mode);
  virtual ~StdIOFile();
  virtual Status<size_t> Read(std::span<std::byte> buf, off_t *off) override;
  virtual Status<size_t> Write(std::span<const std::byte> buf,
                               off_t *off) override;
  virtual Status<int> Stat(struct stat *statbuf, int flags);

  [[nodiscard]] int get_fd() const { return fd_; }

 private:
  int fd_{-1};
};

}  // namespace junction
