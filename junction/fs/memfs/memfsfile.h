// memfsfile.h - support for MemFS files

#pragma once

#include "junction/fs/memfs/memfs.h"

namespace junction::memfs {

class MemFSFile : public SeekableFile {
 public:
  MemFSFile(unsigned int flags, FileMode mode, std::shared_ptr<MemInode> ino)
      : SeekableFile(FileType::kNormal, flags, mode, std::move(ino)) {}

  Status<void> Truncate(off_t newlen) override {
    MemInode &ino = static_cast<MemInode &>(get_inode_ref());
    return ino.SetSize(static_cast<size_t>(newlen));
  }

  Status<size_t> Read(std::span<std::byte> buf, off_t *off) override {
    MemInode &ino = static_cast<MemInode &>(get_inode_ref());
    return ino.Read(buf, off);
  }

  Status<size_t> Write(std::span<const std::byte> buf, off_t *off) override {
    MemInode &ino = static_cast<MemInode &>(get_inode_ref());
    return ino.Write(buf, off);
  }

  [[nodiscard]] size_t get_size() const override {
    const MemInode &ino = static_cast<const MemInode &>(get_inode_ref());
    return ino.get_size();
  }

  Status<void> Stat(struct stat *statbuf) const override {
    const MemInode &ino = static_cast<const MemInode &>(get_inode_ref());
    return ino.GetStats(statbuf);
  }

  Status<void> StatFS(struct statfs *buf) const override {
    const MemInode &ino = static_cast<const MemInode &>(get_inode_ref());
    return ino.GetStatFS(buf);
  }

  Status<void *> MMap(void *addr, size_t length, int prot, int flags,
                      off_t off) override {
    MemInode &ino = static_cast<MemInode &>(get_inode_ref());
    return ino.MMap(addr, length, prot, flags, off);
  }
};

}  // namespace junction::memfs