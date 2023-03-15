// linuxfile.h - support for Linux files
extern "C" {
#include <sys/stat.h>
}

#pragma once

#include <memory>
#include <span>
#include <string_view>

#include "junction/base/error.h"
#include "junction/kernel/file.h"

namespace junction {

class LinuxFile : public File {
  class Token {
    // https://abseil.io/tips/134
   private:
    explicit Token() = default;
    friend LinuxFile;
  };

 public:
  LinuxFile(Token, int fd, int flags, mode_t mode) noexcept;
  virtual ~LinuxFile();

  static std::shared_ptr<LinuxFile> Open(const std::string_view &pathname,
                                         int flags, mode_t mode);
  virtual Status<size_t> Read(std::span<std::byte> buf, off_t *off) override;
  virtual Status<size_t> Write(std::span<const std::byte> buf,
                               off_t *off) override;
  virtual Status<off_t> Seek(off_t off, SeekFrom origin) override;
  virtual Status<void *> MMap(void *addr, size_t length, int prot, int flags,
                              off_t off);
  virtual Status<void> Stat(struct stat *statbuf, int flags) override;
  virtual Status<int> GetDents(void *dirp, unsigned int count) override;
  virtual Status<int> GetDents64(void *dirp, unsigned int count) override;
  virtual Status<void> Ioctl(unsigned long request, char *argp) override;

  [[nodiscard]] int get_fd() const { return fd_; }

 private:
  int fd_{-1};
};

}  // namespace junction
