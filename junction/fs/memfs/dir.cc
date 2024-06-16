// dir.cc - directory support for memfs

#include <map>

#include "junction/base/compiler.h"
#include "junction/base/finally.h"
#include "junction/fs/memfs/memfs.h"

namespace junction::memfs {

Status<std::shared_ptr<Inode>> MemIDir::Lookup(std::string_view name) {
  rt::ScopedSharedLock g(lock_);
  if (auto it = entries_.find(name); it != entries_.end()) return it->second;
  return MakeError(ENOENT);
}

Status<void> MemIDir::MkNod(std::string_view name, mode_t mode, dev_t dev) {
  if ((mode & (kTypeCharacter | kTypeBlock)) == 0) return MakeError(EINVAL);
  auto ino = CreateIDevice(dev, mode);
  return Insert(std::string(name), std::move(ino));
}

Status<void> MemIDir::MkDir(std::string_view name, mode_t mode) {
  auto ino = std::make_shared<MemIDir>(mode, name, get_this());
  return Insert(std::string(name), std::move(ino));
}

Status<void> MemIDir::Unlink(std::string_view name) {
  rt::ScopedLock g(lock_);
  auto it = entries_.find(name);
  if (it == entries_.end()) return MakeError(ENOENT);
  if (it->second->is_dir()) return MakeError(EISDIR);
  it->second->dec_nlink();
  entries_.erase(it);
  return {};
}

Status<void> MemIDir::RmDir(std::string_view name) {
  rt::ScopedLock g(lock_);
  auto it = entries_.find(name);
  if (it == entries_.end()) return MakeError(ENOENT);
  auto *dir = most_derived_cast<MemIDir>(it->second.get());
  if (!dir) return MakeError(ENOTDIR);

  // Confirm the directory is empty
  {
    rt::ScopedLock g(dir->lock_);
    if (!dir->entries_.empty()) return MakeError(ENOTEMPTY);
    dir->dec_nlink();
    assert(dir->is_stale());
  }

  // Remove it
  entries_.erase(it);
  return {};
}

Status<void> MemIDir::SymLink(std::string_view name, std::string_view target) {
  return Insert(std::string(name), CreateISoftLink(target));
}

Status<void> MemIDir::DoRename(MemIDir &src, std::string_view src_name,
                               std::string_view dst_name, bool replace) {
  assert(lock_.IsHeld());
  assert(src.lock_.IsHeld());

  // find the source inode
  auto src_it = src.entries_.find(src_name);
  if (src_it == src.entries_.end()) return MakeError(ENOENT);

  // make sure the destination name doesn't exist already
  if (!replace) {
    auto dst_it = entries_.find(dst_name);
    if (dst_it != entries_.end()) return MakeError(EEXIST);
  }

  // perform the actual rename
  std::shared_ptr<Inode> ino = std::move(src_it->second);
  src.entries_.erase(src_it);

  if (ino->is_dir()) {
    IDir &tdir = static_cast<IDir &>(*ino);
    tdir.SetParent(get_this(), dst_name);
  }

  entries_[std::string(dst_name)] = std::move(ino);
  return {};
}

Status<void> MemIDir::Rename(IDir &src, std::string_view src_name,
                             std::string_view dst_name, bool replace) {
  auto *src_dir = most_derived_cast<MemIDir>(&src);
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
  if (src_dir->get_inum() > this->get_inum()) {
    src_dir->lock_.Lock();
    lock_.Lock();
  } else {
    lock_.Lock();
    src_dir->lock_.Lock();
  }
  return DoRename(*src_dir, src_name, dst_name, replace);
}

Status<void> MemIDir::Link(std::string_view name, std::shared_ptr<Inode> ino) {
  rt::ScopedLock g(lock_);
  if (is_stale()) return MakeError(ESTALE);
  if (Status<void> ret = InsertLocked(std::string(name), std::move(ino)); !ret)
    return MakeError(ret);
  return {};
}

Status<std::shared_ptr<File>> MemIDir::Create(std::string_view name, int flags,
                                              mode_t mode, FileMode fmode) {
  rt::ScopedLock g_(lock_);
  auto it = entries_.find(name);
  if (it == entries_.end()) {
    auto ino = std::make_shared<MemInode>(mode);
    InsertLockedNoCheck(name, ino);
    return ino->Open(flags, fmode);
  }

  if (flags & kFlagExclusive) return MakeError(EEXIST);
  return it->second->Open(flags, fmode);
}

std::vector<dir_entry> MemIDir::GetDents() {
  std::vector<dir_entry> result;
  rt::ScopedSharedLock g(lock_);
  for (const auto &[name, ino] : entries_)
    result.emplace_back(name, ino->get_inum(), ino->get_type());
  return result;
}

Status<void> MemIDir::GetStats(struct stat *buf) const {
  MemInodeToStats(*this, buf);
  return {};
}

// Created a new unattached MemFS folder.
std::shared_ptr<IDir> MkFolder(mode_t mode, std::string &&name,
                               std::shared_ptr<IDir> parent) {
  auto ino =
      std::make_shared<MemIDir>(mode, std::move(name), std::move(parent));
  return ino;
}

}  // namespace junction::memfs
