// memfsfile.h - support for MemFS files

#pragma once

#include "junction/fs/memfs/memfs.h"
#include "junction/snapshot/cereal.h"

namespace junction::memfs {

class MemFSFile : public SeekableFile {
 public:
  MemFSFile(unsigned int flags, FileMode mode, std::shared_ptr<MemInode> ino)
      : SeekableFile(FileType::kNormal, flags, mode, std::move(ino)) {}

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

  template <class Archive>
  void save(Archive &ar) const {
    ar(get_mode(), get_inode());
    ar(cereal::base_class<SeekableFile>(this));
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<MemFSFile> &construct) {
    FileMode mode;
    std::shared_ptr<Inode> ino;
    ar(mode, ino);
    construct(0, mode, std::static_pointer_cast<MemInode>(std::move(ino)));
    ar(cereal::base_class<SeekableFile>(construct.ptr()));
  }
};

}  // namespace junction::memfs