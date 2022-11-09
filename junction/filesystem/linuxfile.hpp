// linux_file.h - support for Linux files

#pragma once

#include <string>

#include "junction/kernel/file.h"

namespace junction {

class LinuxFile : public File {
 public:
  LinuxFile(const std::string_view& pathname, int flags, mode_t mode);
  virtual ~LinuxFile();
  virtual Status<size_t> Read(std::span<std::byte> buf, off_t *off);
  virtual Status<size_t> Write(std::span<const std::byte> buf, off_t *off);
  virtual Status<off_t> Seek(off_t off, SeekFrom origin);
  virtual Status<void> Sync();

  [[nodiscard]] int get_fd() const { return fd_; }

 private:
  int fd_{-1};
};

}  // namespace junction
