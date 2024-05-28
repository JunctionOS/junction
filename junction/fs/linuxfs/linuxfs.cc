
#include "junction/fs/linuxfs/linuxfs.h"

#include "junction/fs/linuxfs/linuxfile.h"

namespace junction::linuxfs {

// A file descriptor pointing to the root of the linux filesystem.
int linux_root_fd = -1;
// TODO(jfried): integrate with chroot.
// The absolute path for the root mount of the linux filesystem.
std::string linux_root = "/";
struct statfs linux_statfs;
std::set<dev_t> allowed_devs;

Status<std::shared_ptr<File>> LinuxInode::Open(uint32_t flags, mode_t mode) {
  int fd = ksys_openat(linux_root_fd, path_.data(), flags, mode);
  if (fd < 0) return nullptr;
  return std::make_shared<LinuxFile>(fd, flags, mode, path_,
                                     shared_from_base<LinuxInode>());
}

Status<std::shared_ptr<IDir>> MountLinux(std::string_view path) {
  struct stat buf;
  int ret = ksys_newfstatat(AT_FDCWD, path.data(), &buf, AT_EMPTY_PATH);
  if (ret) return MakeError(-ret);
  allowed_devs.insert(buf.st_dev);
  auto ino = std::make_shared<LinuxIDir>(buf, std::string(path), std::string{},
                                         std::shared_ptr<IDir>{});
  return std::move(ino);
}

// Setup the linuxfs. Must be called before privileges are dropped.
Status<std::shared_ptr<IDir>> InitLinuxRoot() {
  linux_root_fd = open(linux_root.data(), O_RDONLY | O_PATH);
  if (linux_root_fd < 0) return MakeError(-errno);
  int ret = statfs(linux_root.data(), &linux_statfs);
  if (ret) return MakeError(-ret);
  return MountLinux("/");
}

}  // namespace junction::linuxfs
