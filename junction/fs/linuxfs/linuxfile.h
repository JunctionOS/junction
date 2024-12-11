// linuxfile.h - support for Linux files
#pragma once

#include <memory>
#include <span>

#include "junction/base/error.h"
#include "junction/fs/file.h"
#include "junction/fs/linuxfs/linuxfs.h"
#include "junction/kernel/ksys.h"
#include "junction/snapshot/cereal.h"

namespace junction::linuxfs {

class LinuxFile : public SeekableFile {
 public:
  LinuxFile(KernelFile &&f, int flags, FileMode mode,
            std::shared_ptr<DirectoryEntry> dent) noexcept;
  ~LinuxFile() override;

  Status<size_t> Read(std::span<std::byte> buf, off_t *off) override;
  Status<size_t> Write(std::span<const std::byte> buf, off_t *off) override;
  Status<void *> MMap(void *addr, size_t length, int prot, int flags,
                      off_t off);

  [[nodiscard]] size_t get_size() const override;

  [[nodiscard]] bool SnapshotShareable() const override { return true; }

 private:
  friend class cereal::access;
  friend class LinuxInode;

  template <class Archive>
  void save(Archive &ar) const {
    ar(get_flags(), get_mode());
    save_dent_path(ar);
    ar(cereal::base_class<SeekableFile>(this));
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<LinuxFile> &construct) {
    int flags;
    FileMode mode;
    ar(flags, mode);

    std::shared_ptr<DirectoryEntry> dent = restore_dent_path(ar);

    LinuxInode *inode = fast_cast<LinuxInode *>(&dent->get_inode_ref());
    Status<KernelFile> f = linux_root_fd.OpenAt(inode->get_path(), flags, mode);
    if (unlikely(!f)) throw std::runtime_error("failed to reopen linux file");

    construct(std::move(*f), flags, mode, std::move(dent));
    ar(cereal::base_class<SeekableFile>(construct.ptr()));
  }

  int fd_;
};

}  // namespace junction::linuxfs
