// dir.cc - directory support for linuxfs

#include <map>

#include "junction/base/finally.h"
#include "junction/bindings/log.h"
#include "junction/fs/fs.h"
#include "junction/fs/linuxfs/linuxfile.h"
#include "junction/fs/linuxfs/linuxfs.h"
#include "junction/fs/memfs/memfs.h"
#include "junction/kernel/ksys.h"

namespace junction::linuxfs {

struct linux_dirent64 {
  ino64_t d_ino;           /* 64-bit inode number */
  off64_t d_off;           /* 64-bit offset to next structure */
  unsigned short d_reclen; /* Size of this dirent */
  unsigned char d_type;    /* File type */
  char d_name[];           /* Filename (null-terminated) */
};

class DirectoryIterator {
 public:
  DirectoryIterator(KernelFile &f) : f_(f) {}

  // Gets the next ent name in this directory. The returned string_view is only
  // valid until the next call of GetNext() or the iterator instance is
  // destroyed.
  Status<std::string_view> GetNext() {
    if (pos_ == end_) {
      Status<void> ret = Fill();
      if (!ret) return MakeError(ret);
    }
    linux_dirent64 *ent = reinterpret_cast<linux_dirent64 *>(buf_ + pos_);
    pos_ += ent->d_reclen;
    return std::string_view(ent->d_name);
  }

  template <typename F>
  Status<void> ForEach(F func) {
    dev_t last_dev = -1;
    while (true) {
      Status<std::string_view> ent = GetNext();
      if (!ent) {
        if (ent.error() == EUNEXPECTEDEOF) return {};
        return MakeError(ent);
      }

      if (*ent == ".." || *ent == ".") continue;

      Status<struct stat> stat = f_.StatAt(*ent);
      if (unlikely(!stat)) return MakeError(stat);

      if (stat->st_dev != last_dev) {
        if (!allowed_devs.count(stat->st_dev)) continue;
        last_dev = stat->st_dev;
      }

      Status<void> ret = func(*ent, *stat);
      if (!ret) return ret;
    }
  }

 private:
  Status<void> Fill() {
    long ret = ksys_getdents64(f_.GetFd(), buf_, sizeof(buf_));
    if (ret < 0) return MakeError(-ret);
    if (ret == 0) return MakeError(EUNEXPECTEDEOF);
    pos_ = 0;
    end_ = ret;
    return {};
  }

  KernelFile &f_;
  char buf_[2048];
  size_t pos_{0};
  size_t end_{0};
};

__noinline void LinuxFSPanic(std::string_view msg, Error &err) {
  std::stringstream ss;
  ss << "linuxfs: " << msg << " " << err;
  rt::RuntimeLibcGuard g;
  throw std::runtime_error(ss.str());
}

// Produce a LinuxFS Inode from a stat buf and pathname. May return an empty
// shared ptr with no error if the filetype is not supported.
Status<std::shared_ptr<Inode>> LinuxIDir::ToInode(const struct stat &stat,
                                                  std::string abspath,
                                                  std::string_view entry_name) {
  if (S_ISREG(stat.st_mode))
    return std::make_shared<LinuxInode>(stat, std::move(abspath));

  if (S_ISDIR(stat.st_mode))
    return InstantiateChildDir(stat, std::move(abspath),
                               std::string(entry_name));

  if (S_ISLNK(stat.st_mode)) {
    char buf[PATH_MAX];
    Status<std::string_view> target = linux_root_fd.ReadLinkAt(abspath, {buf});
    if (!target) return MakeError(target);
    return std::make_shared<memfs::MemISoftLink>(stat, *target);
  }

  return {};
}

Status<void> LinuxIDir::FillEntries() {
  assert(lock_.IsHeld());

  Status<KernelFile> fd = GetLinuxDirFD();
  if (!fd) return MakeError(fd);

  DirectoryIterator it(*fd);
  return it.ForEach(
      [&](std::string_view name, struct stat &stat) -> Status<void> {
        Status<std::shared_ptr<Inode>> in =
            ToInode(stat, AppendFileName(name), name);
        if (!in) return MakeError(in);
        if (*in) InsertLockedNoCheck(name, std::move(*in));
        return {};
      });
}

void LinuxIDir::DoInitialize() {
  assert(lock_.IsHeld());
  assert(!is_initialized());
  Status<void> ret = FillEntries();
  if (unlikely(!ret && ret.error() != EACCES))
    LinuxFSPanic("initializing directory", ret.error());
}

//
// Directory functions for writeable LinuxFS.
//

Status<void> LinuxWrIDir::MkDir(std::string_view name, mode_t mode) {
  std::string abspath = AppendFileName(name);
  rt::ScopedLock g(lock_);
  Status<void> ret = linux_root_fd.MkDirAt(abspath, mode);
  if (!ret) return ret;
  if (!is_initialized()) return {};

  Status<struct stat> stat = linux_root_fd.StatAt(abspath.data());
  if (unlikely(!stat)) return MakeError(stat);
  auto ino = std::make_shared<LinuxWrIDir>(*stat, std::move(abspath),
                                           std::string(name), get_this());
  InsertLockedNoCheck(name, std::move(ino));
  return {};
}

Status<void> LinuxWrIDir::Unlink(std::string_view name) {
  std::string abspath = AppendFileName(name);
  rt::ScopedLock g(lock_);
  Status<void> ret = linux_root_fd.UnlinkAt(abspath);
  if (!ret) return ret;
  if (auto it = entries_.find(name); it != entries_.end()) entries_.erase(it);
  return {};
}

Status<void> LinuxWrIDir::RmDir(std::string_view name) {
  std::string abspath = AppendFileName(name);
  rt::ScopedLock g(lock_);
  Status<void> ret = linux_root_fd.UnlinkAt(abspath, AT_REMOVEDIR);
  if (!ret) return ret;
  if (auto it = entries_.find(name); it != entries_.end()) entries_.erase(it);
  return {};
}

Status<void> LinuxWrIDir::SymLink(std::string_view name,
                                  std::string_view target) {
  std::string abspath = AppendFileName(name);
  rt::ScopedLock g(lock_);
  Status<void> ret = linux_root_fd.SymLinkAt(target, abspath);
  if (!ret) return ret;
  if (!is_initialized()) return {};
  Status<struct stat> stat = linux_root_fd.StatAt(abspath);
  if (unlikely(!stat)) LinuxFSPanic("stat after SymLink", stat.error());
  auto ino = std::make_shared<memfs::MemISoftLink>(*stat, target);
  InsertLockedNoCheck(name, std::move(ino));
  return {};
}

Status<void> LinuxWrIDir::DoRename(LinuxWrIDir &src, std::string_view src_name,
                                   std::string_view dst_name, bool replace) {
  assert(lock_.IsHeld());
  assert(src.lock_.IsHeld());

  std::string src_path = src.AppendFileName(src_name);
  std::string dst_path = this->AppendFileName(dst_name);

  Status<void> ret = KernelFile::RenameAt(linux_root_fd, src_path,
                                          linux_root_fd, dst_path, replace);
  if (!ret) return ret;

  std::shared_ptr<Inode> ino;

  // Remove inode from source, if present.
  if (src.is_initialized()) {
    auto src_it = src.entries_.find(src_name);
    if (src_it != src.entries_.end()) {
      ino = std::move(src_it->second);
      src.entries_.erase(src_it);
    }
  }

  // Current directory is not initialized, let's leave it that way.
  if (!is_initialized()) return {};

  // We already have an inode, simply insert it into the entries_ list.
  if (ino) {
    if (ino->is_dir()) {
      IDir &tdir = static_cast<IDir &>(*ino);
      tdir.SetParent(get_this(), std::string(dst_name));
    }
    entries_[std::string(dst_name)] = std::move(ino);
    return {};
  }

  // Create a new Inode instance for the renamed file.
  Status<struct stat> stat = linux_root_fd.StatAt(dst_path);
  if (unlikely(!stat)) return MakeError(stat);
  Status<std::shared_ptr<Inode>> in =
      ToInode(*stat, std::move(dst_path), dst_name);
  if (!in) return MakeError(in);
  if (*in) InsertLockedNoCheck(dst_name, std::move(*in));
  return {};
}

Status<void> LinuxWrIDir::Rename(IDir &src, std::string_view src_name,
                                 std::string_view dst_name, bool replace) {
  auto *src_dir = most_derived_cast<LinuxWrIDir>(&src);
  if (!src_dir) return MakeError(EXDEV);

  // check if rename is in same directory
  if (src_dir == this) {
    rt::ScopedLock g(lock_);
    return DoRename(*src_dir, src_name, dst_name, replace);
  }

  // otherwise rename is across different directories (to avoid deadlock)
  auto fin = finally([this, &src_dir] {
    src_dir->lock_.Unlock();
    lock_.Unlock();
  });
  assert(src_dir->get_inum() != this->get_inum());
  if (src_dir->get_inum() > this->get_inum()) {
    src_dir->lock_.Lock();
    lock_.Lock();
  } else {
    lock_.Lock();
    src_dir->lock_.Lock();
  }
  return DoRename(*src_dir, src_name, dst_name, replace);
}

Status<void> LinuxWrIDir::Link(std::string_view name,
                               std::shared_ptr<Inode> ino) {
  auto *src_ino = most_derived_cast<LinuxInode>(ino.get());
  if (!src_ino) return MakeError(EXDEV);

  std::string abspath = AppendFileName(name);

  rt::ScopedLock g(lock_);
  Status<void> ret = KernelFile::LinkAt(linux_root_fd, src_ino->get_path(),
                                        linux_root_fd, abspath);
  if (!ret) return ret;
  if (is_initialized()) InsertLockedNoCheck(name, std::move(ino));
  return {};
}

inline std::shared_ptr<LinuxInode> CastToLinuxInode(std::shared_ptr<Inode> in) {
  if constexpr (is_debug_build())
    return std::dynamic_pointer_cast<LinuxInode>(std::move(in));
  return std::static_pointer_cast<LinuxInode>(std::move(in));
}

Status<std::shared_ptr<File>> LinuxWrIDir::Create(std::string_view name,
                                                  int flags, mode_t mode,
                                                  FileMode fmode) {
  assert(flags & O_CREAT);
  std::string abspath = AppendFileName(name);
  std::shared_ptr<LinuxInode> ino;
  rt::ScopedLock g(lock_);
  Status<KernelFile> f = linux_root_fd.OpenAt(abspath, flags, fmode, mode);
  if (!f) return MakeError(f);

  if (!is_initialized()) {
    DoInitialize();
    MarkInitialized();
  }

  auto it = entries_.find(name);
  if (it != entries_.end()) {
    ino = CastToLinuxInode(it->second);
  } else {
    Status<struct stat> stat = f->StatAt();
    if (unlikely(!stat)) LinuxFSPanic("bad stat after O_CREAT", stat.error());

    Status<std::shared_ptr<Inode>> in =
        ToInode(*stat, std::move(abspath), name);
    if (unlikely(!in)) LinuxFSPanic("inode create after O_CREAT", in.error());
    if (!*in) return MakeError(EINVAL);

    InsertLockedNoCheck(name, *in);
    ino = CastToLinuxInode(std::move(*in));
  }

  return std::make_shared<LinuxFile>(std::move(*f), flags, fmode,
                                     std::move(abspath), std::move(ino));
}

}  // namespace junction::linuxfs
