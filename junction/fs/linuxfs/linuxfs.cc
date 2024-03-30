
#include "junction/fs/linuxfs/linuxfs.h"

#include "junction/fs/linuxfs/linuxfile.h"

namespace junction::linuxfs {

// A file descriptor pointing to the root of the linux filesystem.
int linux_root_fd = -1;
// TODO(jfried): integrate with chroot.
// The absolute path for the root mount of the linux filesystem.
const char *linux_root = "/";
struct statfs linux_statfs;

Status<std::shared_ptr<File>> LinuxInode::Open(uint32_t flags, mode_t mode) {
  int fd = ksys_openat(linux_root_fd, path_.data(), flags, mode);
  if (fd < 0) return nullptr;
  return std::make_shared<LinuxFile>(LinuxFile::Token{}, fd, flags, mode, path_,
                                     get_this());
}

// Setup the linuxfs. Must be called before privileges are dropped.
Status<std::shared_ptr<IDir>> InitLinuxFs() {
  linux_root_fd = open(linux_root, O_RDONLY | O_PATH);
  if (linux_root_fd < 0) return MakeError(-errno);
  struct stat buf;
  int ret = ksys_newfstatat(linux_root_fd, ".", &buf, AT_EMPTY_PATH);
  if (ret) return MakeError(-ret);
  ret = statfs(linux_root, &linux_statfs);
  if (ret) return MakeError(-ret);
  auto ino = std::make_shared<LinuxIDir>(buf, ".", std::string{},
                                         std::shared_ptr<IDir>{});
  return ino;
}

}  // namespace junction::linuxfs