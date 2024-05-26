
#include "junction/fs/linuxfs/linuxfs.h"

#include "junction/fs/linuxfs/linuxfile.h"

namespace junction::linuxfs {

// A file descriptor pointing to the root of the linux filesystem.
int linux_root_fd = -1;
// TODO(jfried): integrate with chroot.
// The absolute path for the root mount of the linux filesystem.
std::string linux_root = "/";
std::vector<std::string> allowed_mounts = {
    "/tmp",
    "/home",
};
struct statfs linux_statfs;
std::set<dev_t> allowed_devs;

Status<std::shared_ptr<File>> LinuxInode::Open(uint32_t flags, mode_t mode) {
  int fd = ksys_openat(linux_root_fd, path_.data(), flags, mode);
  if (fd < 0) return nullptr;
  return std::make_shared<LinuxFile>(fd, flags, mode, path_,
                                     shared_from_base<LinuxInode>());
}

// Setup the linuxfs. Must be called before privileges are dropped.
Status<std::shared_ptr<IDir>> InitLinuxFs() {
  linux_root_fd = open(linux_root.data(), O_RDONLY | O_PATH);
  if (linux_root_fd < 0) return MakeError(-errno);
  struct stat buf;
  for (const auto &mount : allowed_mounts) {
    int ret = ksys_newfstatat(AT_FDCWD, mount.data(), &buf, AT_EMPTY_PATH);
    if (ret) return MakeError(-ret);
    allowed_devs.insert(buf.st_dev);
  }
  int ret =
      ksys_newfstatat(linux_root_fd, linux_root.data(), &buf, AT_EMPTY_PATH);
  if (ret) return MakeError(-ret);
  allowed_devs.insert(buf.st_dev);
  ret = statfs(linux_root.data(), &linux_statfs);
  if (ret) return MakeError(-ret);
  auto ino = std::make_shared<LinuxIDir>(buf, ".", std::string{},
                                         std::shared_ptr<IDir>{});
  return ino;
}

}  // namespace junction::linuxfs
