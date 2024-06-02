// linuxfile.h - support for Linux files
extern "C" {
#include <sys/stat.h>
}

#pragma once

#include <memory>
#include <span>
#include <string_view>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/fs/file.h"
#include "junction/fs/linuxfs/linuxfs.h"
#include "junction/kernel/ksys.h"
#include "junction/snapshot/cereal.h"

namespace junction::linuxfs {

class LinuxFile : public SeekableFile {
 public:
  LinuxFile(KernelFile &&f, int flags, mode_t mode, std::string &&pathname,
            std::shared_ptr<LinuxInode> ino) noexcept;
  LinuxFile(KernelFile &&f, int flags, mode_t mode, std::string_view pathname,
            std::shared_ptr<LinuxInode> ino) noexcept;
  virtual ~LinuxFile();

  virtual Status<size_t> Read(std::span<std::byte> buf, off_t *off) override;
  virtual Status<size_t> Write(std::span<const std::byte> buf,
                               off_t *off) override;
  virtual Status<void *> MMap(void *addr, size_t length, int prot, int flags,
                              off_t off);
  virtual Status<void> Ioctl(unsigned long request, char *argp) override;

  [[nodiscard]] int get_fd() const { return fd_; }
  [[nodiscard]] size_t get_size() const override;

 private:
  friend class cereal::access;
  friend class LinuxInode;

  template <class Archive>
  void save(Archive &ar) const {
    ar(get_filename(), get_flags(), get_mode());
    ar(cereal::base_class<SeekableFile>(this));
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<LinuxFile> &construct) {
    std::string filename;
    int flags;
    mode_t mode;
    ar(filename, flags, mode);

    Status<std::shared_ptr<Inode>> tmp =
        LookupInode(FSRoot::GetGlobalRoot(), filename, false);
    if (unlikely(!tmp)) {
      LOG(ERR) << "failed to re-open linux file " << filename;
      BUG();
    }

    LinuxInode *ino;
    if constexpr (is_debug_build())
      ino = dynamic_cast<LinuxInode *>(tmp->get());
    else
      ino = reinterpret_cast<LinuxInode *>(tmp->get());

    Status<KernelFile> f = linux_root_fd.OpenAt(filename, flags, mode);
    if (!f) {
      LOG(ERR) << "failed to open file " << filename << " ret: " << f.error();
      BUG();
    }

    construct(std::move(*f), flags, mode, std::move(filename),
              std::static_pointer_cast<LinuxInode>(std::move(*tmp)));
    ar(cereal::base_class<SeekableFile>(construct.ptr()));
  }

  int fd_;
};

}  // namespace junction::linuxfs
