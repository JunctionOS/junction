extern "C" {
#include <sys/stat.h>
#include <sys/statfs.h>
}

#include <iostream>
#include <memory>
#include <string>
#include <string_view>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/filesystem/linuxfs.h"
#include "junction/filesystem/memfs.h"
#include "junction/filesystem/vfs.h"
#include "junction/kernel/file.h"

namespace junction {

VFS::VFS(const std::string_view& config_file_path) noexcept
    : fs_{std::make_shared<MemFS>(config_file_path),
          std::make_shared<LinuxFS>()} {}

VFS::VFS() noexcept
    : fs_{std::make_shared<MemFS>(), std::make_shared<LinuxFS>()} {}

FileSystem* VFS::get_fs(const std::string_view& pathname, uint32_t mode = 0,
                        uint32_t flags = 0) {
  for (const auto& fs : fs_) {
    if (fs->is_supported(pathname, mode, flags)) return &(*fs);
  }
  return nullptr;
}

Status<std::shared_ptr<File>> VFS::Open(const std::string_view& pathname,
                                        uint32_t mode, uint32_t flags) {
  FileSystem* fs = get_fs(pathname, mode, flags);
  if (unlikely(!fs)) return MakeError(EINVAL);
  return fs->Open(pathname, mode, flags);
}

Status<void> VFS::StatFS(const std::string_view& pathname, struct statfs* buf) {
  FileSystem* fs = get_fs(pathname);
  if (unlikely(!fs)) return MakeError(EINVAL);
  return fs->StatFS(pathname, buf);
}

Status<void> VFS::Stat(const std::string_view& pathname, struct stat* buf) {
  FileSystem* fs = get_fs(pathname);
  if (unlikely(!fs)) return MakeError(EINVAL);
  return fs->Stat(pathname, buf);
}

Status<void> VFS::CreateDirectory(const std::string_view& pathname,
                                  uint32_t mode) {
  constexpr uint32_t flags = kFlagCreate;
  FileSystem* fs = get_fs(pathname, mode, flags);
  if (unlikely(!fs)) return MakeError(EINVAL);
  return fs->CreateDirectory(pathname, mode);
}

Status<void> VFS::RemoveDirectory(const std::string_view& pathname) {
  FileSystem* fs = get_fs(pathname);
  if (unlikely(!fs)) return MakeError(EINVAL);
  return fs->RemoveDirectory(pathname);
}

Status<void> VFS::Link(const std::string_view& oldpath,
                       const std::string_view& newpath) {
  FileSystem* fs = get_fs(oldpath);
  if (unlikely(!fs)) return MakeError(EINVAL);
  FileSystem* fs_newpath = get_fs(newpath);
  if (unlikely(fs != fs_newpath)) return MakeError(EINVAL);
  return fs->Link(oldpath, newpath);
}

Status<void> VFS::Unlink(const std::string_view& pathname) {
  FileSystem* fs = get_fs(pathname);
  if (unlikely(!fs)) return MakeError(EINVAL);
  return fs->Unlink(pathname);
}

}  // namespace junction
