// memfs.h - internal definitions for memfs

#pragma once

#include "junction/base/slab_list.h"
#include "junction/fs/dev.h"
#include "junction/fs/file.h"
#include "junction/fs/fs.h"

namespace junction::memfs {

inline constexpr __fsword_t TMPFS_MAGIC = 0x01021994;
inline constexpr size_t kBlockSize = 4096;
inline constexpr size_t kMaxSizeBytes = (1UL << 33);  // 8 GB

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
std::shared_ptr<ISoftLink> CreateISoftLink(std::string_view path);
// Create a character or block device inode.
std::shared_ptr<Inode> CreateIDevice(dev_t dev, mode_t mode);

class MemInode : public Inode {
 public:
  MemInode(mode_t mode)
      : Inode(kTypeRegularFile | mode, AllocateInodeNumber()) {}
  Status<void> SetSize(size_t newlen) override;
  Status<void> GetStats(struct stat *buf) const override;

  Status<size_t> Read(std::span<std::byte> buf, off_t *off) {
    const size_t n = std::min(buf.size(), buf_.size() - *off);
    std::copy_n(buf_.cbegin() + *off, n, buf.begin());
    *off += n;
    return n;
  }

  Status<size_t> Write(std::span<const std::byte> buf, off_t *off) {
    if (buf_.size() - *off < buf.size()) buf_.Resize(buf.size() + *off);
    std::copy_n(buf.begin(), buf.size(), buf_.begin() + *off);
    *off += buf.size();
    return buf.size();
  }

  // Open a file for this inode.
  Status<std::shared_ptr<File>> Open(uint32_t flags, mode_t mode) override;

  Status<void> GetStatFS(struct statfs *buf) const override {
    StatFs(buf);
    return {};
  }

  [[nodiscard]] size_t get_size() const { return buf_.size(); }

 private:
  // file contents
  SlabList<kBlockSize> buf_;
};

}  // namespace junction::memfs
