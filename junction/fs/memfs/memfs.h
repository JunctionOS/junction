// memfs.h - internal definitions for memfs

#pragma once

#include <map>

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

inline bool NeedsTrace() {
  return IsJunctionThread() && unlikely(myproc().get_mem_map().TraceEnabled());
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
    if (unlikely(NeedsTrace())) {
      auto it = traced_inodes_.find(get_inum());
      size_t off_s = static_cast<size_t>(*off);
      // Only record accesses to parts of the file that existed when tracing
      // started.
      if (it != traced_inodes_.end() && off_s < it->second) {
        myproc().get_mem_map().RecordHit(buf_ + off_s,
                                         std::min(n, it->second - off_s),
                                         Time::Now(), PROT_READ);
      }
    }
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
    if (unlikely(NeedsTrace())) {
      auto it = traced_inodes_.find(get_inum());
      // Only record accesses to parts of the file that existed when tracing
      // started.
      if (it != traced_inodes_.end() && off < it->second) {
        myproc().get_mem_map().RecordHit(buf_ + off,
                                         std::min(buf.size(), it->second - off),
                                         Time::Now(), PROT_WRITE);
      }
    }
    std::memcpy(buf_ + off, buf.data(), buf.size());
    *off_off += buf.size();
    return buf.size();
  }

  // Open a file for this inode.
  Status<std::shared_ptr<File>> Open(
      uint32_t flags, FileMode mode,
      std::shared_ptr<DirectoryEntry> dent) override;

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

  void RegisterInodeForTracing() {
    auto [_it, inserted] = traced_inodes_.try_emplace(get_inum(), size_);
    assert(inserted);
  }

  static void ClearTracedMap() { traced_inodes_.clear(); }

 private:
  // Protects modifications to buf_. A reader lock holder can read/write to buf_
  // but a writer lock must be used to resize buf_.
  rt::SharedMutex lock_;
  // File contents.
  char *const buf_;
  size_t size_{0};
  const off_t extent_offset_;

  // Snapshot of MemFS data present at beginning of memory access tracing.
  static std::map<ino_t, size_t> traced_inodes_;
};

class MemIDir : public IDir {
 public:
  MemIDir(Token t, mode_t mode, ino_t ino = AllocateInodeNumber())
      : IDir(t, mode, ino, IDirType::kMem) {}
  MemIDir(Token t, const struct stat &stat) : IDir(t, stat, IDirType::kMem) {}

  // Directory ops
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

  template <class Archive>
  void save(Archive &ar) const {
    assert(is_most_derived<MemIDir>(*this));
    ar(get_mode(), get_inum());
    ar(initialized_, cereal::base_class<IDir>(this));
    const_cast<MemIDir *>(this)->ForEach([&](DirectoryEntry &dent) {
      if (dent.WillBeSerialized())
        GetSnapshotContext().dents.emplace_back(dent.shared_from_this());
    });
  }

  // Called when a MemIDir is instantiated.
  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<MemIDir> &construct) {
    mode_t mode;
    ino_t inum;
    ar(mode, inum);
    construct(IDir::CerealGetToken(), mode, inum);
    ar(construct->initialized_, cereal::base_class<IDir>(construct.ptr()));
  }

 protected:
  // Subclasses override this to add custom logic run on the first access of
  // this directory (e.g. to populate entries).
  virtual void DoInitialize(){};

  Status<std::shared_ptr<DirectoryEntry>> LookupMissLocked(
      std::string_view name) override;

  [[nodiscard]] bool is_initialized() const {
    return load_acquire(&initialized_);
  }
  void MarkInitialized() { store_release(&initialized_, true); }
  void ClearInitialized() { store_release(&initialized_, false); }

  __always_inline void DoInitCheck() {
    if (unlikely(!is_initialized())) RunInitialize();
  }

  __always_inline void DoInitCheckLocked() {
    if (unlikely(!is_initialized())) RunInitializeLocked();
  }

  [[nodiscard]] Status<void> Insert(std::string name,
                                    std::shared_ptr<Inode> ino) {
    rt::ScopedLock g(lock_);
    return AddDentLocked(std::move(name), std::move(ino));
  }

 private:
  bool initialized_{false};

  __noinline void RunInitializeLocked() {
    DoInitialize();
    MarkInitialized();
  }

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
    assert(is_most_derived<MemISoftLink>(*this));
    ar(get_inum(), path_);
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
