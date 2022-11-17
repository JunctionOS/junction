// linuxfile.h - support for Linux files

#pragma once

#include <span>
#include <string_view>

#include "junction/base/error.h"
#include "junction/kernel/file.h"

namespace junction {

class LinuxFile : public File {
 public:
  LinuxFile(const std::string_view &pathname, int flags, mode_t mode);
  virtual ~LinuxFile();
  virtual Status<size_t> Read(std::span<std::byte> buf, off_t *off) override;
  virtual Status<size_t> Write(std::span<const std::byte> buf,
                               off_t *off) override;
  virtual Status<off_t> Seek(off_t off, SeekFrom origin) override;
  virtual Status<void> Sync() override;

  [[nodiscard]] int get_fd() const { return fd_; }

 private:
  int fd_{-1};
};

}  // namespace junction
