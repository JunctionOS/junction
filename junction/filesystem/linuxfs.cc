extern "C" {
#include <sys/statfs.h>
}

#include <memory>
#include <string>
#include <string_view>

#include "junction/base/error.h"
#include "junction/base/string.h"
#include "junction/bindings/log.h"
#include "junction/filesystem/linuxfile.h"
#include "junction/filesystem/linuxfs.h"
#include "junction/kernel/file.h"
#include "junction/kernel/ksys.h"

namespace junction {

Status<std::shared_ptr<File>> LinuxFS::Open(const std::string_view &pathname,
                                            uint32_t mode, uint32_t flags) {
  flags &= ~kFlagCreate;
  auto ret = LinuxFile::Open(pathname, flags, mode);
  if (!ret) return MakeError(EINVAL);
  return ret;
}

Status<void> LinuxFS::StatFS(const std::string_view &pathname,
                             struct statfs *buf) {
  int ret = ksys_statfs(pathname.data(), buf);
  if (ret < 0) return MakeError(-ret);
  return {};
}

Status<void> LinuxFS::Stat(const std::string_view &pathname, struct stat *buf) {
  int ret = ksys_newfstatat(AT_FDCWD, pathname.data(), buf, 0 /* flags */);
  if (ret < 0) return MakeError(-ret);
  return {};
}

bool LinuxFS::is_supported([[maybe_unused]] const std::string_view &pathname,
                           uint32_t mode, uint32_t flags) {
  // Creating new files is not allowed.
  if (flags & kFlagCreate) return false;
  // Writing to files is not allowed.
  if (mode & (kModeWrite | kModeReadWrite)) return false;
  // Read-only access to files that are present in the file system is allowed.
  return true;
}

}  // namespace junction
