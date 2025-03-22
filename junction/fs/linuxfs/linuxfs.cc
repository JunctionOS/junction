
#include "junction/fs/linuxfs/linuxfs.h"

#include "junction/fs/linuxfs/linuxfile.h"

namespace junction::linuxfs {

// A file descriptor pointing to the root of the linux filesystem.
KernelFile linux_root_fd;
// TODO(jfried): integrate with chroot.
// The absolute path for the root mount of the linux filesystem.
std::string linux_root = "/";
struct statfs linux_statfs;
std::set<dev_t> allowed_devs;

Status<std::shared_ptr<File>> LinuxInode::Open(
    uint32_t flags, FileMode mode, std::shared_ptr<DirectoryEntry> dent) {
  // If we have an Inode for it, it already exists.
  unsigned int linux_flags = flags & ~(kFlagCreate | kFlagExclusive);
  if constexpr (!linux_fs_writeable()) {
    if (mode != FileMode::kRead) return MakeError(EPERM);
  }
  Status<KernelFile> f = linux_root_fd.OpenAt(get_path(), linux_flags, mode);
  if (!f) return MakeError(f);
  return std::make_shared<LinuxFile>(std::move(*f), flags, mode,
                                     std::move(dent));
}

[[nodiscard]] off_t LinuxInode::get_size() const {
  if constexpr (!linux_fs_writeable()) return size_;
  Status<struct stat> stat = linux_root_fd.StatAt(path_);
  if (unlikely(!stat)) LinuxFSPanic("bad stat", stat.error());
  return stat->st_size;
}

Status<void> LinuxInode::SetSize(size_t size) {
  if constexpr (!linux_fs_writeable()) return MakeError(EACCES);
  long ret = ksyscall(__NR_truncate, path_.data(), size);
  if (ret < 0) return MakeError(-ret);
  return {};
}

Status<void> MountLinux(IDir &parent, std::string name, std::string_view path) {
  struct stat buf;
  int ret = ksys_newfstatat(AT_FDCWD, path.data(), &buf, AT_EMPTY_PATH);
  if (ret) return MakeError(-ret);
  allowed_devs.insert(buf.st_dev);
  if constexpr (linux_fs_writeable())
    parent.AddIDirNoCheck<LinuxWrIDir>(std::move(name), buf, std::string(path));
  else
    parent.AddIDirNoCheck<LinuxIDir>(std::move(name), buf, std::string(path));
  return {};
}

// Setup the linuxfs. Must be called before privileges are dropped.
Status<std::shared_ptr<IDir>> InitLinuxRoot() {
  Status<KernelFile> f = KernelFile::Open(linux_root, O_PATH, FileMode::kRead);
  if (unlikely(!f)) return MakeError(f);
  linux_root_fd = std::move(*f);
  int ret = statfs(linux_root.data(), &linux_statfs);
  if (unlikely(ret)) return MakeError(-ret);

  Status<struct stat> buf = linux_root_fd.StatAt();
  if (unlikely(!buf)) return MakeError(buf);

  std::shared_ptr<IDir> root;
  if constexpr (linux_fs_writeable())
    root = std::make_shared<LinuxWrIDir>(IDir::GetInitToken(), *buf,
                                         std::string{"/"});
  else
    root = std::make_shared<LinuxIDir>(IDir::GetInitToken(), *buf,
                                       std::string{"/"});
  auto sp = std::make_shared<DirectoryEntry>(
      std::string{}, std::shared_ptr<DirectoryEntry>{}, root);
  sp->SetRootEntry();
  root->SetParent(std::move(sp));
  return root;
}

}  // namespace junction::linuxfs
