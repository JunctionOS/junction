// memfsfile.h - file implementation to use with MemFS
extern "C" {
#include <sys/stat.h>
}

#pragma once

#include <memory>
#include <span>
#include <string>
#include <string_view>

#include "junction/base/error.h"
#include "junction/filesystem/memfs.h"
#include "junction/kernel/file.h"

namespace junction {

class MemFSFile : public File {
  class Token {
    // https://abseil.io/tips/134
   private:
    explicit Token() = default;
    friend MemFSFile;
  };

 public:
  MemFSFile(Token, const std::string_view &name, int flags, mode_t mode,
            const std::shared_ptr<MemFSInode> inode) noexcept;
  ~MemFSFile() override = default;

  static std::shared_ptr<MemFSFile> Open(
      const std::string_view &name, int flags, mode_t mode,
      const std::shared_ptr<MemFSInode> inode);
  virtual Status<size_t> Read(std::span<std::byte> buf, off_t *off) override;
  virtual Status<size_t> Write(std::span<const std::byte> buf,
                               off_t *off) override;
  virtual Status<void> Truncate(off_t newlen) override;
  virtual Status<void> Allocate(int mode, off_t offset, off_t len) override;
  virtual Status<off_t> Seek(off_t off, SeekFrom origin) override;
  virtual Status<void *> MMap(void *addr, size_t length, int prot, int flags,
                              off_t off);
  virtual Status<void> Stat(struct stat *statbuf, int flags) override;
  virtual Status<int> GetDents(void *dirp, unsigned int count) override;
  virtual Status<int> GetDents64(void *dirp, unsigned int count) override;

 private:
  const std::string name_;
  const std::shared_ptr<MemFSInode> inode_;
};

}  // namespace junction
