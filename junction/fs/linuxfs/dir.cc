// dir.cc - directory support for linuxfs

#include <map>

#include "junction/bindings/log.h"
#include "junction/fs/fs.h"
#include "junction/fs/linuxfs/linuxfs.h"
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

// Get the list of entries for this directory from the Linux file system.
Status<void> LinuxIDir::FillEntries() {
  assert(lock_.IsHeld());
  Status<KernelFile> f =
      KernelFile::OpenAt(linux_root_fd, path_, O_DIRECTORY | O_RDONLY, S_IRUSR);
  if (!f) return MakeError(f);

  DirectoryIterator it(*f);
  while (true) {
    Status<std::string_view> ent = it.GetNext();
    if (!ent) {
      if (ent.error() == EUNEXPECTEDEOF) break;
      return MakeError(ent);
    }

    if (*ent == ".." || *ent == ".") continue;

    struct stat stat;
    int ret =
        ksys_newfstatat(f->GetFd(), ent->data(), &stat, AT_SYMLINK_NOFOLLOW);
    if (ret != 0) return MakeError(-ret);

    if (stat.st_dev != root_dev) continue;

    std::string filename(*ent);
    std::string abspath(path_ + "/" + filename);

    std::shared_ptr<Inode> ino;
    if (S_ISREG(stat.st_mode)) {
      ino = std::make_shared<LinuxInode>(stat, std::move(abspath));
    } else if (S_ISDIR(stat.st_mode)) {
      ino = std::make_shared<LinuxIDir>(stat, std::move(abspath), filename,
                                        get_this());
    } else if (S_ISLNK(stat.st_mode)) {
      char buf[PATH_MAX];
      ssize_t wret =
          ksys_readlinkat(f->GetFd(), filename.data(), buf, sizeof(buf));
      if (wret < 0) return MakeError(-wret);
      ino = std::make_shared<LinuxISoftLink>(stat, std::move(abspath),
                                             std::string_view(buf, wret));
    } else {
      continue;
    }
    InsertLocked(std::move(filename), std::move(ino));
  }

  return {};
}

bool LinuxIDir::Initialize() {
  assert(lock_.IsHeld());
  assert(!initialized_);
  Status<void> ret = FillEntries();
  initialized_ = true;
  return (ret || ret.error() == EACCES);
}

Status<std::shared_ptr<Inode>> LinuxIDir::Lookup(std::string_view name) {
  rt::MutexGuard g(lock_);
  if (unlikely(!initialized_)) Initialize();
  if (auto it = entries_.find(name); it != entries_.end()) return it->second;
  return MakeError(ENOENT);
}

std::vector<dir_entry> LinuxIDir::GetDents() {
  std::vector<dir_entry> result;
  rt::MutexGuard g(lock_);
  if (unlikely(!initialized_)) Initialize();
  for (const auto &[name, ino] : entries_)
    result.emplace_back(name, ino->get_inum(), ino->get_type());
  return result;
}

}  // namespace junction::linuxfs
