// dir.cc - directory support for memfs

#include <map>

#include "junction/base/compiler.h"
#include "junction/base/finally.h"
#include "junction/fs/memfs/memfs.h"

namespace junction::memfs {

namespace {

class MemIDir : public IDir {
 public:
  MemIDir(mode_t mode, std::shared_ptr<IDir> parent)
      : IDir(mode, AllocateInodeNumber(), parent) {}

  // Directory ops
  Status<std::shared_ptr<Inode>> Lookup(std::string_view name) override;
  Status<void> MkNod(std::string_view name, mode_t mode, dev_t dev) override;
  Status<void> MkDir(std::string_view name, mode_t mode) override;
  Status<void> Unlink(std::string_view name) override;
  Status<void> RmDir(std::string_view name) override;
  Status<void> SymLink(std::string_view name, std::string_view path) override;
  Status<void> Rename(IDir &src, std::string_view src_name,
                      std::string_view dst_name) override;
  Status<void> Link(std::string_view name, std::shared_ptr<Inode> ino) override;
  Status<std::shared_ptr<File>> Create(std::string_view name,
                                       mode_t mode) override;
  std::vector<dir_entry> GetDents() override;

  // Inode ops
  Status<struct stat> GetStats() override;

 private:
  // Helper routine for inserting an inode.
  Status<void> Insert(std::string name, std::shared_ptr<Inode> ino);
  // Helper routine for renaming.
  Status<void> DoRename(MemIDir &src, std::string_view src_name,
                        std::string_view dst_name);

  rt::Mutex lock_;
  std::map<std::string, std::shared_ptr<Inode>, std::less<>> entries_;
};

Status<void> MemIDir::Insert(std::string name, std::shared_ptr<Inode> ino) {
  rt::MutexGuard g(lock_);
  if (is_stale()) return MakeError(ESTALE);
  auto [it, okay] = entries_.try_emplace(std::move(name), std::move(ino));
  if (!okay) return MakeError(EEXIST);
  ino->inc_nlink();
  return {};
}

Status<std::shared_ptr<Inode>> MemIDir::Lookup(std::string_view name) {
  rt::MutexGuard g(lock_);
  if (auto it = entries_.find(name); it != entries_.end()) return it->second;
  return MakeError(ENOENT);
}

Status<void> MemIDir::MkNod(std::string_view name, mode_t mode, dev_t dev) {
  if ((mode & (kTypeCharacter | kTypeBlock)) == 0) return MakeError(EINVAL);
  auto ino = CreateIDevice(dev, mode);
  return Insert(std::string(name), std::move(ino));
}

Status<void> MemIDir::MkDir(std::string_view name, mode_t mode) {
  auto ino = std::make_shared<MemIDir>(mode, get_this());
  return Insert(std::string(name), std::move(ino));
}

Status<void> MemIDir::Unlink(std::string_view name) {
  rt::MutexGuard g(lock_);
  auto it = entries_.find(name);
  if (it == entries_.end()) return MakeError(ENOENT);
  if (it->second->is_dir()) return MakeError(EISDIR);
  it->second->dec_nlink();
  entries_.erase(it);
  return {};
}

Status<void> MemIDir::RmDir(std::string_view name) {
  rt::MutexGuard g(lock_);
  auto it = entries_.find(name);
  if (it == entries_.end()) return MakeError(ENOENT);
  auto *dir = most_derived_cast<MemIDir>(it->second.get());
  if (!dir) return MakeError(ENOTDIR);

  // Confirm the directory is empty
  {
    rt::MutexGuard g(dir->lock_);
    if (!dir->entries_.empty()) return MakeError(ENOTEMPTY);
    dir->dec_nlink();
    assert(dir->is_stale());
  }

  // Remove it
  entries_.erase(it);
  return {};
}

Status<void> MemIDir::SymLink(std::string_view name, std::string_view path) {
  return Insert(std::string(name), CreateISoftLink(path));
}

Status<void> MemIDir::DoRename(MemIDir &src, std::string_view src_name,
                               std::string_view dst_name) {
  assert(lock_.IsHeld());
  assert(src.lock_.IsHeld());

  // find the source inode
  auto src_it = src.entries_.find(src_name);
  if (src_it == src.entries_.end()) return MakeError(ENOENT);

  // make sure the destination name doesn't exist already
  auto dst_it = entries_.find(dst_name);
  if (dst_it != entries_.end()) return MakeError(EEXIST);

  // perform the actual rename
  std::shared_ptr<Inode> ino = std::move(src_it->second);
  src.entries_.erase(src_it);
  entries_[std::string(dst_name)] = std::move(ino);
  return {};
}

Status<void> MemIDir::Rename(IDir &src, std::string_view src_name,
                             std::string_view dst_name) {
  auto *src_dir = most_derived_cast<MemIDir>(&src);
  if (!src_dir) return MakeError(EXDEV);

  // check if rename is in same directory
  if (src_dir == this) {
    rt::MutexGuard g(lock_);
    return DoRename(*src_dir, src_name, dst_name);
  }

  // otherwise rename is across different directories (so avoid deadlock)
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
  return DoRename(*src_dir, src_name, dst_name);
}

Status<void> MemIDir::Link(std::string_view name, std::shared_ptr<Inode> ino) {
  if (Status<void> ret = Insert(std::string(name), ino); !ret)
    return MakeError(ret);
  return {};
}

Status<std::shared_ptr<File>> MemIDir::Create(std::string_view name,
                                              mode_t mode) {}

std::vector<dir_entry> MemIDir::GetDents() {
  std::vector<dir_entry> result;
  rt::MutexGuard g(lock_);
  for (const auto &[name, ino] : entries_)
    result.emplace_back(name, ino->get_inum(), ino->get_type());
  return result;
}

Status<struct stat> MemIDir::GetStats() { return MemInodeToStats(*this); }

}  // namespace

}  // namespace junction::memfs
