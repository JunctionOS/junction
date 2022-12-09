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
 public:
  static std::shared_ptr<LinuxFile> Open(const std::string_view &pathname,
                                         int flags, mode_t mode);

  virtual ~LinuxFile();
  virtual Status<size_t> Read(std::span<std::byte> buf, off_t *off) override;
  virtual Status<size_t> Write(std::span<const std::byte> buf,
                               off_t *off) override;
  virtual Status<off_t> Seek(off_t off, SeekFrom origin) override;
  virtual Status<void *> MMap(void *addr, size_t length, int prot, int flags,
                              off_t off);
  virtual Status<int> Stat(struct stat *statbuf, int flags);
  virtual Status<int> GetDents(void *dirp, unsigned int count);
  virtual Status<int> GetDents64(void *dirp, unsigned int count);

  [[nodiscard]] int get_fd() const { return fd_; }

 private:
  LinuxFile(int fd, int flags, mode_t mode) noexcept;

  int fd_{-1};

  struct MakeSharedEnabler;
};

/* This is needed to support std::make_shared for LinuxFile. */
struct LinuxFile::MakeSharedEnabler : public LinuxFile {
  MakeSharedEnabler(int fd, int flags, mode_t mode) noexcept
      : LinuxFile(fd, flags, mode) {}
};

}  // namespace junction
