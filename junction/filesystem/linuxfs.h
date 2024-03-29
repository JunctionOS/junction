// linuxfs.h - support for a Linux filesystem

#pragma once

#include <memory>
#include <string>
#include <string_view>

#include "junction/base/error.h"
#include "junction/kernel/file.h"
#include "junction/kernel/fs.h"

namespace junction {

#ifdef WRITEABLE_LINUX_FS
constexpr bool linux_fs_writeable() { return true; }
#else
constexpr bool linux_fs_writeable() { return false; }
#endif

class LinuxFS : public FileSystem {
 public:
  LinuxFS() noexcept {}
  ~LinuxFS() override = default;
  virtual Status<std::shared_ptr<File>> Open(const std::string_view &pathname,
                                             uint32_t mode,
                                             uint32_t flags) override;
  virtual Status<void> Access(const std::string_view &pathname,
                              uint32_t mode) override;
  virtual Status<void> StatFS(const std::string_view &pathname,
                              struct statfs *buf) override;
  virtual Status<void> Stat(const std::string_view &pathname,
                            struct stat *buf) override;
  virtual bool is_supported(const std::string_view &pathname, uint32_t mode,
                            uint32_t flags) override;
  // Operations required for write support
  virtual Status<void> CreateDirectory(const std::string_view &pathname,
                                       uint32_t mode) override;
  virtual Status<void> RemoveDirectory(
      const std::string_view &pathname) override;
  virtual Status<void> Link(const std::string_view &oldpath,
                            const std::string_view &newpath) override;
  virtual Status<void> Unlink(const std::string_view &pathname) override;
};

}  // namespace junction
