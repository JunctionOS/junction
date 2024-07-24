// dir.cc - directory support for memfs

#include <map>

#include "junction/base/compiler.h"
#include "junction/base/finally.h"
#include "junction/fs/memfs/memfs.h"

namespace junction::memfs {

Status<std::shared_ptr<DirectoryEntry>> MemIDir::LookupMissLocked(
    std::string_view name) {
  DoInitCheckLocked();
  return FindShared(name);
}

Status<void> MemIDir::MkNod(std::string_view name, mode_t mode, dev_t dev) {
  DoInitCheck();
  if ((mode & (kTypeCharacter | kTypeBlock)) == 0) return MakeError(EINVAL);
  auto ino = CreateIDevice(dev, mode);
  return Insert(std::string(name), std::move(ino));
}

Status<void> MemIDir::MkDir(std::string_view name, mode_t mode) {
  DoInitCheck();
  rt::ScopedLock g(lock_);
  return AddIDirLocked<MemIDir>(std::string(name), mode);
}

Status<void> MemIDir::Unlink(std::string_view name) {
  DoInitCheck();
  rt::ScopedLock g(lock_);
  Status<DirectoryEntry *> dent = FindRaw(name);
  if (!dent) return MakeError(ENOENT);
  Inode &ino = (*dent)->get_inode_ref();
  if (ino.is_dir()) return MakeError(EISDIR);
  UnlinkAndDispose(*dent);
  return {};
}

Status<void> MemIDir::RmDir(std::string_view name) {
  DoInitCheck();
  rt::ScopedLock g(lock_);
  Status<DirectoryEntry *> dent = FindRaw(name);
  if (!dent) return MakeError(ENOENT);
  Inode &ino = (*dent)->get_inode_ref();
  if (!ino.is_dir()) return MakeError(ENOTDIR);
  if (static_cast<IDir &>(ino).get_idir_type() != IDirType::kMem)
    return MakeError(EXDEV);

  MemIDir &dir = static_cast<MemIDir &>(ino);
  // Confirm the directory is empty
  {
    rt::ScopedLock g(dir.lock_);
    if (dir.size()) return MakeError(ENOTEMPTY);
  }

  UnlinkAndDispose(*dent);
  return {};
}

Status<void> MemIDir::SymLink(std::string_view name, std::string_view target) {
  DoInitCheck();
  return Insert(std::string(name), CreateISoftLink(std::string(target)));
}

Status<void> MemIDir::Rename(IDir &src, std::string_view src_name,
                             std::string_view dst_name, bool replace) {
  DoInitCheck();
  if (src.get_idir_type() != IDirType::kMem) return MakeError(EXDEV);
  MemIDir *src_dir = static_cast<MemIDir *>(&src);

  // check if rename is in same directory
  if (src_dir == this) {
    rt::ScopedLock g(lock_);
    return MoveFrom(*src_dir, src_name, dst_name, replace);
  }

  // otherwise rename is across different directories (to avoid deadlock)
  auto fin = finally([this, &src_dir] {
    src_dir->lock_.Unlock();
    lock_.Unlock();
  });
  if (src_dir->get_inum() > this->get_inum()) {
    src_dir->lock_.Lock();
    lock_.Lock();
  } else {
    lock_.Lock();
    src_dir->lock_.Lock();
  }
  return MoveFrom(*src_dir, src_name, dst_name, replace);
}

Status<void> MemIDir::Link(std::string_view name, std::shared_ptr<Inode> ino) {
  DoInitCheck();
  rt::ScopedLock g(lock_);
  if (is_stale()) return MakeError(ESTALE);
  return AddDentLocked(std::string(name), std::move(ino));
}

Status<std::shared_ptr<File>> MemIDir::Create(std::string_view name, int flags,
                                              mode_t mode, FileMode fmode) {
  DoInitCheck();
  rt::ScopedLock g_(lock_);
  Status<DirectoryEntry *> dent = FindRaw(name);
  if (dent) {
    if (flags & kFlagExclusive) return MakeError(EEXIST);
    return (*dent)->Open(flags, fmode);
  }

  Status<std::shared_ptr<MemInode>> ino = MemInode::Create(mode);
  if (unlikely(!ino)) return MakeError(ino);
  DirectoryEntry *d = AddDentLockedNoCheck(std::string(name), std::move(*ino));
  return d->Open(flags, fmode);
}

std::vector<dir_entry> MemIDir::GetDents() {
  DoInitCheck();
  std::vector<dir_entry> result;
  ForEach([&](const DirectoryEntry &dent) {
    result.emplace_back(dent.entry_info());
  });
  return result;
}

Status<void> MemIDir::GetStats(struct stat *buf) const {
  MemInodeToStats(*this, buf);
  return {};
}

// Created a new unattached MemFS folder.
std::shared_ptr<IDir> MkFolder(IDir &parent, std::string name, mode_t mode) {
  std::shared_ptr<DirectoryEntry> de =
      parent.AddIDirNoCheck<MemIDir>(std::move(name), mode);
  return static_cast<IDir &>(de->get_inode_ref()).get_this();
}

}  // namespace junction::memfs
