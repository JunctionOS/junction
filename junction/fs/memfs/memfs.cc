// misc.cc - support for miscellaneous inode types

#include "junction/fs/memfs/memfs.h"

#include "junction/fs/memfs/memfsfile.h"

namespace junction::memfs {

namespace {

// MemIDevice is an inode type for character and block devices
class MemIDevice : public Inode {
 public:
  MemIDevice(dev_t dev, mode_t mode, ino_t inum = AllocateInodeNumber())
      : Inode(mode, inum), dev_(dev) {}

  Status<std::shared_ptr<File>> Open(uint32_t flags, FileMode mode) override {
    return DeviceOpen(*this, dev_, flags, mode);
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

Status<void> MemInode::SetSize(size_t newlen) {
  if (unlikely(newlen > kMaxSizeBytes)) return MakeError(EINVAL);
  rt::ScopedLock g_(lock_);
  buf_.Resize(newlen);
  return {};
}

Status<void> MemInode::GetStats(struct stat *buf) const {
  MemInodeToStats(*this, buf);
  buf->st_size = buf_.size();
  buf->st_blocks = 0;
  return {};
}

Status<std::shared_ptr<File>> MemInode::Open(uint32_t flags, FileMode mode) {
  return std::make_shared<MemFSFile>(flags, mode, shared_from_base<MemInode>());
}

std::shared_ptr<ISoftLink> CreateISoftLink(std::string path) {
  return std::make_shared<MemISoftLink>(std::move(path));
}

std::shared_ptr<Inode> CreateIDevice(dev_t dev, mode_t mode) {
  return std::make_shared<MemIDevice>(dev, mode);
}

}  // namespace junction::memfs

CEREAL_REGISTER_TYPE(junction::memfs::MemInode);
CEREAL_REGISTER_TYPE(junction::memfs::MemIDir);
CEREAL_REGISTER_TYPE(junction::memfs::MemISoftLink);
CEREAL_REGISTER_TYPE(junction::memfs::MemIDevice);
