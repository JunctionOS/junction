// dir.cc - directory support for memfs

#include <map>

#include "junction/base/compiler.h"
#include "junction/fs/fs.h"

namespace junction {

namespace {

class MemIDir : public IDir {
 public:
  MemIDir(mode_t mode, ino_t inum, std::shared_ptr<IDir> parent)
      : IDir(mode, inum, parent) {}

  // Directory ops
  Status<std::shared_ptr<Inode>> Lookup(std::string_view name) override;
  Status<void> MkNod(std::string_view name, mode_t mode, dev_t dev) override;
  Status<void> MkDir(std::string_view name, mode_t mode) override;
  Status<void> Unlink(std::string_view name) override;
  Status<void> RmDir(std::string_view name) override;
  Status<void> SymLink(std::string_view name, std::string_view path) override;
  Status<void> Rename(IDir &src, std::string_view src_name,
                      std::string_view dst_name) override;
  Status<void> Link(Inode &node, std::string_view name) override;
  Status<std::shared_ptr<File>> Create(std::string_view name,
                                       mode_t mode) override;
  std::vector<dir_entry> GetDents() override;

  // Inode ops
  Status<struct stat> GetAttributes() override;
  Status<void> SetAttributes(struct stat attr) override;

 private:
  rt::Mutex lock_;
  std::map<std::string, std::shared_ptr<Inode>> entries_;
};

Status<std::shared_ptr<Inode>> MemIDir::Lookup(std::string_view name) {
  rt::MutexGuard g(lock_);
  if (auto it = entries_.find(name); it != entries_.end()) return it->second;
  return MakeError(ENOENT);
}

Status<void> MemIDir::MkNod(std::string_view name, mode_t mode, dev_t dev) {}

Status<void> MemIDir::MkDir(std::string_view name, mode_t mode) {
  auto dir = std::make_shared<MemIDir>(mode, 0, get_this());
  std::string nbuf(name);
  rt::MutexGuard g(lock_);
  auto [it, okay] = entries_.try_emplace(std::move(nbuf), std::move(dir));
  if (!okay) return MakeError(EEXIST);
  return {}
}

Status<void> MemIDir::Unlink(std::string_view name) {
  rt::MutexGuard g(lock_);
  auto it = entries_.find(name);
  if (it == entries_.end()) return MakeError(ENOENT);
  if (it->second->get_type() == kTypeDirectory) return MakeError(EISDIR);
  entries_.erase(it);
  return {};
}

Status<void> MemIDir::RmDir(std::string_view name) {
  rt::MutexGuard g(lock_);
  auto it = entries_.find(name);
  if (it == entries_.end()) return MakeError(ENOENT);
  if (it->second->get_type() != kTypeDirectory) return MakeError(ENOTDIR);
  entries_.erase(it);
  return {};
}

Status<void> MemIDir::SymLink(std::string_view name, std::string_view path) {}

Status<void> MemIDir::DoRename(MemIDir &src, std::string_view src_name,
                               std::string_view dst_name) {}

Status<void> MemIDir::Rename(IDir &src, std::string_view src_name,
                             std::string_view dst_name) {
  auto *msrc = most_derived_cast<MemIDir>(src);
  if (!msrc) return MakeError(EXDEV);

  // check if rename is in same directory
  if (msrc == ths) {
    rt::SpinGuard g(lock_);
    return DoRename(msrc, src_name, dst_name);
  }

  // otherwise rename is across different directories (so avoid deadlock)
  auto fin = finally([this, msrc] {
    msrc->Lock.Unlock();
    lock_.Unlock();
  });
  if (msrc->get_inum() > this->get_inum()) {
    msrc->lock_.Lock();
    lock_.Lock();
  } else {
    lock_.Lock();
    msrc->lock_.Lock();
  }

  return DoRename(msrc, src_name, dst_name);
}

Status<void> MemIDir::Link(Inode &node, std::string_view name) {}

Status<std::shared_ptr<File>> MemIDir::Create(std::string_view name,
                                              mode_t mode) {}

std::vector<dir_entry> MemIDir::GetDents() {
  std::vector<dir_entry> result;
  rt::MutexGuard g(lock_);
  for (const auto &ent : entries) {
    Inode &ino = *ent.second.get();
    result.emplace_back(ent.first, ino.get_inum(), ino.get_type());
  }
  return result;
}

Status<struct stat> MemIDir::GetAttributes() {
  struct stat s = InodeToAttributes(*this);
  s.st_nlink = 1;
  s.st_blksize = kPageSize;
  return s;
}

Status<void> MemIDir::SetAttributes(struct stat attr) {
  return MakeError(EINVAL);
}

}  // namespace

}  // namespace junction
