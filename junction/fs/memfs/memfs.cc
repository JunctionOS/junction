// memfs.cc - support for memfs inode types

extern "C" {
#include <sys/mman.h>
}

#include "junction/base/bitmap.h"
#include "junction/bindings/log.h"
#include "junction/fs/memfs/memfs.h"
#include "junction/fs/memfs/memfsfile.h"
#include "junction/kernel/ksys.h"

#ifndef MFD_EXEC
#define MFD_FLAGS 0
#else
#define MFD_FLAGS MFD_EXEC
#endif

namespace junction::memfs {

namespace {

// File descriptor of open memfd used to back memfs files.
int memfs_extent_fd;
// Lock protecting @allocated_files_slots.
rt::Spin file_alloc_lock;
// Bitmap of allocated slots in the memfd area.
bitmap<kMaxFiles> allocated_file_slots;
// Temp hack for memfs serialization/loading with elf.
std::atomic_size_t next_memfs_faddr{0x380000000000};

// MemIDevice is an inode type for character and block devices
class MemIDevice : public Inode {
 public:
  MemIDevice(dev_t dev, mode_t mode, ino_t inum = AllocateInodeNumber())
      : Inode(mode, inum), dev_(dev) {}

  Status<std::shared_ptr<File>> Open(
      uint32_t flags, FileMode mode,
      std::shared_ptr<DirectoryEntry> dent) override {
    return DeviceOpen(std::move(dent), dev_, flags, mode);
  }
  Status<void> GetStats(struct stat *buf) const override {
    MemInodeToStats(*this, buf);
    buf->st_rdev = dev_;
    return {};
  }
  Status<void> GetStatFS(struct statfs *buf) const override {
    StatFs(buf);
    return {};
  }

  template <class Archive>
  void save(Archive &ar) const {
    ar(dev_, get_mode(), get_inum());
    ar(cereal::base_class<Inode>(this));
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<MemIDevice> &construct) {
    dev_t dev;
    mode_t mode;
    ino_t inum;
    ar(dev, mode, inum);
    construct(dev, mode, inum);
    ar(cereal::base_class<Inode>(construct.ptr()));
  }

 private:
  dev_t dev_;
};

}  // namespace

Status<void> SaveMemFs(cereal::BinaryOutputArchive &ar) {
  ar(allocated_file_slots, next_memfs_faddr);
  return {};
}

Status<void> RestoreMemFs(cereal::BinaryInputArchive &ar) {
  ar(allocated_file_slots, next_memfs_faddr);
  return {};
}

MemInode::~MemInode() {
  // Drop backing pages.
  if (extent_offset_ != -1) {
    Status<void> ret = KernelMAdvise(buf_, kMaxSizeBytes, MADV_REMOVE);
    if (unlikely(!ret))
      LOG(WARN) << "meminode: failed to remove pages " << ret.error();
  }

  Status<void> ret = KernelMUnmap(buf_, kMaxSizeBytes);
  if (unlikely(!ret)) LOG(WARN) << "failed to unmap memfs " << ret.error();

  if (extent_offset_ == -1) return;

  rt::SpinGuard g(file_alloc_lock);
  allocated_file_slots.clear(extent_offset_);
}

Status<std::shared_ptr<MemInode>> MemInode::Create(mode_t mode) {
  size_t off;
  {
    rt::SpinGuard g(file_alloc_lock);
    std::optional<size_t> tmp = allocated_file_slots.find_next_clear(0);
    if (unlikely(!tmp)) return MakeError(ENOSPC);
    off = *tmp;
    allocated_file_slots.set(off);
  }

  uintptr_t nextp =
      next_memfs_faddr.fetch_add(kMaxSizeBytes, std::memory_order_relaxed);
  intptr_t ret = ksys_mmap(reinterpret_cast<void *>(nextp), kMaxSizeBytes,
                           PROT_READ | PROT_WRITE, MAP_SHARED, memfs_extent_fd,
                           off * kMaxSizeBytes);
  if (unlikely(ret < 0)) return MakeError(-ret);
  return std::make_shared<MemInode>(Token{}, reinterpret_cast<char *>(ret), off,
                                    mode);
}

Status<void *> MemInode::MMap(void *addr, size_t length, int prot, int flags,
                              off_t off) {
  // TODO(jf): support mapping restored memfs files.
  if (extent_offset_ == -1) return MakeError(EINVAL);

  assert(!(flags & MAP_ANONYMOUS));
  intptr_t ret = ksys_mmap(addr, length, prot, flags, memfs_extent_fd,
                           extent_offset_ * kMaxSizeBytes + off);
  if (unlikely(ret < 0)) return MakeError(-ret);
  return reinterpret_cast<void *>(ret);
}

Status<void> MemInode::SetSize(size_t newlen) {
  if (unlikely(newlen > kMaxSizeBytes)) return MakeError(EINVAL);
  rt::ScopedLock g_(lock_);

  size_t newlen_p = PageAlign(newlen);
  size_t oldlen_p = PageAlign(size_);
  if (newlen_p < oldlen_p) {
    // Zero dropped blocks.
    int advice = extent_offset_ == -1 ? MADV_DONTNEED : MADV_REMOVE;
    Status<void> ret =
        KernelMAdvise(buf_ + newlen_p, oldlen_p - newlen_p, advice);
    if (unlikely(!ret))
      LOG(WARN) << "meminode: failed to remove pages " << ret.error();
  }
  size_ = newlen;
  return {};
}

Status<void> MemInode::GetStats(struct stat *buf) const {
  MemInodeToStats(*this, buf);
  buf->st_size = size_;
  buf->st_blocks = 0;
  return {};
}

Status<std::shared_ptr<File>> MemInode::Open(
    uint32_t flags, FileMode mode, std::shared_ptr<DirectoryEntry> dent) {
  return std::make_shared<MemFSFile>(flags, mode, std::move(dent));
}

std::shared_ptr<ISoftLink> CreateISoftLink(std::string path) {
  return std::make_shared<MemISoftLink>(std::move(path));
}

std::shared_ptr<Inode> CreateIDevice(dev_t dev, mode_t mode) {
  return std::make_shared<MemIDevice>(dev, mode);
}

Status<void> InitMemfs() {
  memfs_extent_fd = memfd_create("memfs", MFD_FLAGS);
  if (memfs_extent_fd < 0) return MakeError(errno);

  int ret = ftruncate(memfs_extent_fd, kMaxMemfdExtent);
  if (ret < 0) return MakeError(errno);

  return {};
}

std::map<ino_t, size_t> MemInode::traced_inodes_;

void MemFSStartTracer(IDir &root) {
  std::function<void(DirectoryEntry & cur)> fn([&](DirectoryEntry &cur) {
    MemInode *ino = dynamic_cast_guarded<MemInode *>(&cur.get_inode_ref());
    if (ino) ino->RegisterInodeForTracing();
    if (!cur.get_inode_ref().is_dir()) return;
    IDir &dir = static_cast<IDir &>(cur.get_inode_ref());
    dir.ForEach(fn);
  });
  root.ForEach(fn);
}

void MemFSEndTracer() { MemInode::ClearTracedMap(); }

}  // namespace junction::memfs

CEREAL_REGISTER_TYPE(junction::memfs::MemInode);
CEREAL_REGISTER_TYPE(junction::memfs::MemIDir);
CEREAL_REGISTER_TYPE(junction::memfs::MemISoftLink);
CEREAL_REGISTER_TYPE(junction::memfs::MemIDevice);
CEREAL_REGISTER_TYPE(junction::memfs::MemFSFile);
