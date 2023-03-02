// vfs.h - virtual filesystem

#pragma once

extern "C" {
#include <sys/stat.h>
#include <sys/statfs.h>
}

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "junction/base/error.h"
#include "junction/kernel/file.h"
#include "junction/kernel/fs.h"

namespace junction {

class VFS : public FileSystem {
 public:
  VFS() noexcept;
  VFS(const std::string_view &config_file_path) noexcept;
  ~VFS() override = default;
  virtual Status<std::shared_ptr<File>> Open(const std::string_view &pathname,
                                             uint32_t mode,
                                             uint32_t flags) override;
  virtual Status<void> CreateDirectory(const std::string_view &pathname,
                                       uint32_t mode) override;
  virtual Status<void> RemoveDirectory(
      const std::string_view &pathname) override;
  virtual Status<void> StatFS(const std::string_view &pathname,
                              struct statfs *buf) override;
  virtual Status<void> Stat(const std::string_view &pathname,
                            struct stat *buf) override;
  virtual Status<void> Link(const std::string_view &oldpath,
                            const std::string_view &newpath) override;
  virtual Status<void> Unlink(const std::string_view &pathname) override;

 private:
  // list of available file systems.
  // order matters; the first file system that supports a given path prefix will
  // be used and further scanning will not be done.
  std::vector<std::shared_ptr<FileSystem>> fs_;

  FileSystem *get_fs(const std::string_view &pathname, uint32_t mode,
                     uint32_t flags);
};

}  // namespace junction
