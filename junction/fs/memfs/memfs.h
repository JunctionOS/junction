// memfs.h - internal definitions for memfs

#pragma once

#include "junction/base/slab_list.h"
#include "junction/fs/dev.h"
#include "junction/fs/file.h"
#include "junction/fs/fs.h"
#include "junction/snapshot/snapshot.h"

namespace junction::memfs {

inline constexpr __fsword_t TMPFS_MAGIC = 0x01021994;
inline constexpr size_t kBlockSize = 4096;
inline constexpr size_t kMaxSizeBytes = (1UL << 30);                  // 1 GB
inline constexpr size_t kMaxMemfdExtent = (1UL << 45);                // 35 TB
inline constexpr size_t kMaxFiles = kMaxMemfdExtent / kMaxSizeBytes;  // 32K

inline void StatFs(struct statfs *buf) {
  buf->f_type = TMPFS_MAGIC;
  buf->f_bsize = kPageSize;
  buf->f_namelen = 255;
}

// Generate file attributes. Does not set st_size.
inline void MemInodeToStats(const Inode &ino, struct stat *buf) {
  InodeToStats(ino, buf);
  buf->st_blksize = kPageSize;
  buf->st_dev = MakeDevice(8, 0);  // fake SCSI device
}

// Create a soft link inode.
std::shared_ptr<ISoftLink> CreateISoftLink(std::string path);
// Create a character or block device inode.
std::shared_ptr<Inode> CreateIDevice(dev_t dev, mode_t mode);

class MemInode : public Inode {
  class Token {
    explicit Token() = default;
    friend MemInode;
  };

 public:
  MemInode(Token, char *buf, off_t off, mode_t mode,
           ino_t inum = AllocateInodeNumber())
      : Inode(kTypeRegularFile | mode, inum), buf_(buf), extent_offset_(off) {}
  ~MemInode() override;

  // Create a new MemInode.
  static Status<std::shared_ptr<MemInode>> Create(mode_t mode);

  Status<void> SetSize(size_t newlen) override;
  Status<void> GetStats(struct stat *buf) const override;

  Status<size_t> Read(std::span<std::byte> buf, off_t *off) {
    rt::ScopedSharedLock g_(lock_);
    const size_t n = std::min(buf.size(), size_ - *off);
    std::memcpy(buf.data(), buf_ + *off, n);
    *off += n;
    return n;
  }

  Status<size_t> Write(std::span<const std::byte> buf, off_t *off_off) {
    size_t off = static_cast<size_t>(*off_off);
    if (unlikely(off >= kMaxSizeBytes)) return MakeError(ENOSPC);
    // Truncate buf if it will overflow our max size.
    if (unlikely(buf.size() > kMaxSizeBytes - off))
      buf = buf.subspan(0, kMaxSizeBytes - off);
    rt::ScopedSharedLock g_(lock_);
    if (off + buf.size() > size_) {
      lock_.UpgradeLock();
      if (off + buf.size() > size_) size_ = off + buf.size();
      lock_.DowngradeLock();
    }
    std::memcpy(buf_ + off, buf.data(), buf.size());
    *off_off += buf.size();
    return buf.size();
  }

  // Open a file for this inode.
  Status<std::shared_ptr<File>> Open(uint32_t flags, FileMode mode) override;

  Status<void> GetStatFS(struct statfs *buf) const override {
    StatFs(buf);
    return {};
  }

  Status<void *> MMap(void *addr, size_t length, int prot, int flags,
                      off_t off);

  [[nodiscard]] size_t get_size() const { return size_; }

  template <class Archive>
  void save(Archive &ar) const {
    ar(get_mode(), get_inum(), reinterpret_cast<uintptr_t>(buf_));
    ar(size_);
    ar(cereal::base_class<Inode>(this));
    GetSnapshotContext().mem_areas_.emplace_back(buf_, size_, kMaxSizeBytes);
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<MemInode> &construct) {
    mode_t mode;
    ino_t inum;
    uintptr_t buf;
    ar(mode, inum, buf);
    construct(Token{}, reinterpret_cast<char *>(buf), -1, mode, inum);
    ar(construct->size_);
    ar(cereal::base_class<Inode>(construct.ptr()));
  }

 private:
  // Protects modifications to buf_. A reader lock holder can read/write to buf_
  // but a writer lock must be used to resize buf_.
  rt::SharedMutex lock_;
  // File contents.
  char *const buf_;
  size_t size_{0};
  const off_t extent_offset_;
};

class MemIDir : public IDir {
 public:
  MemIDir(mode_t mode, std::string name, std::shared_ptr<IDir> parent,
          ino_t ino = AllocateInodeNumber())
      : IDir(mode, ino, std::move(name), IDirType::kMem, parent) {}
  MemIDir(const struct stat &stat, std::string name,
          std::shared_ptr<IDir> parent)
      : IDir(stat, std::move(name), IDirType::kMem, parent) {}

  // Directory ops
  Status<std::shared_ptr<Inode>> Lookup(std::string_view name) override;
  Status<void> MkNod(std::string_view name, mode_t mode, dev_t dev) override;
  Status<void> MkDir(std::string_view name, mode_t mode) override;
  Status<void> Unlink(std::string_view name) override;
  Status<void> RmDir(std::string_view name) override;
  Status<void> SymLink(std::string_view name, std::string_view target) override;
  Status<void> Rename(IDir &src, std::string_view src_name,
                      std::string_view dst_name, bool replace) override;
  Status<void> Link(std::string_view name, std::shared_ptr<Inode> ino) override;
  Status<std::shared_ptr<File>> Create(std::string_view name, int flags,
                                       mode_t mode, FileMode fmode) override;
  std::vector<dir_entry> GetDents() override;

  // Inode ops
  Status<void> GetStats(struct stat *buf) const override;
  Status<void> GetStatFS(struct statfs *buf) const override {
    StatFs(buf);
    return {};
  }

  void PruneForSnapshot() override {
    for (auto &[name, in] : entries_) {
      if (in->is_dir()) {
        IDir *id = static_cast<IDir *>(in.get());
        id->PruneForSnapshot();
      }
    }
  }

  Status<void> Mount(std::string name, std::shared_ptr<Inode> ino) override {
    rt::ScopedLock g(lock_);
    InsertLockedNoCheck(name, ino);
    if (ino->is_dir()) {
      IDir &dir = static_cast<IDir &>(*ino);
      dir.SetParent(get_this(), std::move(name));
    }
    return {};
  }

  Status<void> Unmount(std::string_view name) override {
    rt::ScopedLock g(lock_);
    auto it = entries_.find(name);
    if (it == entries_.end()) return MakeError(ENOENT);
    it->second->dec_nlink();
    entries_.erase(it);
    return {};
  }

  template <class Archive>
  void save(Archive &ar) const {
    if (is_most_derived<MemIDir>(*this))
      ar(get_mode(), get_inum(), get_parent(), get_name());
    ar(initialized_, entries_);
    ar(cereal::base_class<IDir>(this));
  }

  // Used only by derived classes.
  template <class Archive>
  void load(Archive &ar) {
    assert(!is_most_derived<MemIDir>(*this));
    ar(initialized_, entries_);
    ar(cereal::base_class<IDir>(this));
  }

  // Called when a MemIDir is instantiated.
  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<MemIDir> &construct) {
    mode_t mode;
    ino_t inum;
    std::shared_ptr<IDir> parent;
    std::string name_in_parent;
    ar(mode, inum, parent, name_in_parent);
    construct(mode, std::move(name_in_parent), std::move(parent), inum);
    ar(construct->initialized_, construct->entries_);
    ar(cereal::base_class<IDir>(construct.ptr()));
  }

 protected:
  // Subclasses override this to add custom logic run on the first access of
  // this directory.
  virtual void DoInitialize(){};

  [[nodiscard]] bool is_initialized() const {
    return load_acquire(&initialized_);
  }
  void MarkInitialized() { store_release(&initialized_, true); }
  void ClearInitialized() { store_release(&initialized_, false); }

  __always_inline void DoInitCheck() {
    if (unlikely(!is_initialized())) RunInitialize();
  }
  std::map<std::string, std::shared_ptr<Inode>, std::less<>> entries_;

  void InsertLockedNoCheck(std::string_view name, std::shared_ptr<Inode> ino) {
    assert(lock_.IsHeld());
    ino->inc_nlink();
    entries_[std::string(name)] = std::move(ino);
  }

  [[nodiscard]] Status<void> InsertLocked(std::string name,
                                          std::shared_ptr<Inode> ino) {
    assert(lock_.IsHeld());
    auto [it, okay] = entries_.try_emplace(std::move(name), std::move(ino));
    if (!okay) return MakeError(EEXIST);
    it->second->inc_nlink();
    return {};
  }

  [[nodiscard]] Status<void> Insert(std::string name,
                                    std::shared_ptr<Inode> ino) {
    rt::ScopedLock g(lock_);
    return InsertLocked(std::move(name), std::move(ino));
  }

 private:
  bool initialized_{false};
  // Helper routine for renaming.
  Status<void> DoRename(MemIDir &src, std::string_view src_name,
                        std::string_view dst_name, bool replace);

  __noinline void RunInitialize() {
    rt::ScopedLock g(lock_);
    if (likely(!initialized_)) {
      DoInitialize();
      MarkInitialized();
    }
  }
};

// MemISoftLink is an inode type for soft link
class MemISoftLink : public ISoftLink {
 public:
  MemISoftLink(std::string path, ino_t ino = AllocateInodeNumber())
      : ISoftLink(0777, ino), path_(std::move(path)) {}
  MemISoftLink(const struct stat &stat, std::string path)
      : ISoftLink(stat), path_(std::move(path)) {}
  ~MemISoftLink() override = default;

  std::string ReadLink() const override { return path_; }
  Status<void> GetStats(struct stat *buf) const override {
    MemInodeToStats(*this, buf);
    return {};
  }

  Status<void> GetStatFS(struct statfs *buf) const override {
    StatFs(buf);
    return {};
  }

  template <class Archive>
  void save(Archive &ar) const {
    if (is_most_derived<MemISoftLink>(*this)) ar(get_inum(), path_);
    ar(cereal::base_class<ISoftLink>(this));
  }

  template <class Archive>
  void load(Archive &ar) {
    assert(!is_most_derived<MemISoftLink>(*this));
    ar(cereal::base_class<ISoftLink>(this));
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<MemISoftLink> &construct) {
    ino_t inum;
    std::string path;
    ar(inum, path);
    construct(std::move(path), inum);
    ar(cereal::base_class<ISoftLink>(construct.ptr()));
  }

 private:
  const std::string path_;
};

}  // namespace junction::memfs
