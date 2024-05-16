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
  if constexpr (!linux_fs_writeable()) flags &= ~kFlagCreate;
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
  if constexpr (linux_fs_writeable()) return true;

  // Creating new files is not allowed.
  if (flags & kFlagCreate) return false;
  // Writing to files is not allowed.
  if (mode & (kModeWrite | kModeReadWrite)) return false;
  // Read-only access to files that are present in the file system is allowed.
  return true;
}

// Operations required for write support
Status<void> LinuxFS::CreateDirectory(const std::string_view &pathname,
                                      uint32_t mode) {
  if constexpr (!linux_fs_writeable()) return MakeError(EINVAL);

  // TODO: ensure that pathname has null terminator.
  long ret = ksys_default(reinterpret_cast<long>(pathname.data()), mode, 0, 0,
                          0, 0, __NR_mkdir);
  if (ret) return MakeError(-ret);
  return {};
}

Status<void> LinuxFS::Access(const std::string_view &pathname, uint32_t mode) {
  // TODO: ensure that pathname has null terminator.
  long ret = ksys_default(reinterpret_cast<long>(pathname.data()), mode, 0, 0,
                          0, 0, __NR_access);
  if (ret) return MakeError(-ret);
  return {};
}

Status<void> LinuxFS::RemoveDirectory(const std::string_view &pathname) {
  if constexpr (!linux_fs_writeable()) return MakeError(EINVAL);

  // TODO: ensure that pathname has null terminator.
  long ret = ksys_default(reinterpret_cast<long>(pathname.data()), 0, 0, 0, 0,
                          0, __NR_rmdir);
  if (ret) return MakeError(-ret);
  return {};
}

Status<void> LinuxFS::Link(const std::string_view &oldpath,
                           const std::string_view &newpath) {
  if constexpr (!linux_fs_writeable()) return MakeError(EINVAL);

  long ret = ksys_default(reinterpret_cast<long>(oldpath.data()),
                          reinterpret_cast<long>(newpath.data()), 0, 0, 0, 0,
                          __NR_link);
  if (ret) return MakeError(-ret);
  return {};
}

Status<void> LinuxFS::Unlink(const std::string_view &pathname) {
  if constexpr (!linux_fs_writeable()) return MakeError(EINVAL);

  long ret = ksys_default(reinterpret_cast<long>(pathname.data()), 0, 0, 0, 0,
                          0, __NR_unlink);
  if (ret) return MakeError(-ret);
  return {};
}

}  // namespace junction
