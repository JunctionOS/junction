// linuxfs.h - support for a Linux filesystem

#pragma once

#include <memory>
#include <string>
#include <string_view>

#include "junction/base/error.h"
#include "junction/kernel/file.h"
#include "junction/kernel/fs.h"

namespace junction {

class LinuxFS : public FileSystem {
 public:
  LinuxFS() noexcept {}
  ~LinuxFS() override = default;
  virtual Status<std::shared_ptr<File>> Open(const std::string_view &pathname,
                                             uint32_t mode,
                                             uint32_t flags) override;
  virtual Status<void> StatFS(const std::string_view &pathname,
                              struct statfs *buf) override;
  virtual Status<void> Stat(const std::string_view &pathname,
                            struct stat *buf) override;
  virtual bool is_supported(const std::string_view &pathname, uint32_t mode,
                            uint32_t flags) override;
};

}  // namespace junction
