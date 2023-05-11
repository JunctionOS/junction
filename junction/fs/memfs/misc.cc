// misc.cc - support for miscellaneous inode types

#include "junction/fs/memfs/memfs.h"

namespace junction::memfs {

namespace {

// MemISoftLink is an inode type for soft link
class MemISoftLink : public ISoftLink {
 public:
  MemISoftLink(std::string_view path, ino_t inum)
      : ISoftLink(0, inum), path_(path) {}
  ~MemISoftLink() override = default;

  Status<std::string> ReadLink() override;
  Status<struct stat> GetStats() override;

 private:
  const std::string path_;
};

Status<std::string> MemISoftLink::ReadLink() { return path_; }

Status<struct stat> MemISoftLink::GetStats() { return MemInodeToStats(*this); }

// MemIDevice is an inode type for character and block devices
class MemIDevice : public Inode {
 public:
  MemIDevice(dev_t dev, mode_t mode, ino_t inum)
      : Inode(mode, inum), dev_(dev) {}

  Status<std::shared_ptr<File>> Open(mode_t mode, uint32_t flags) override;
  Status<struct stat> GetStats() override;

 private:
  dev_t dev_;
};

Status<std::shared_ptr<File>> MemIDevice::Open(mode_t mode, uint32_t flags) {
  return DeviceOpen(*this, dev_, mode, flags);
}

Status<struct stat> MemIDevice::GetStats() {
  struct stat st = MemInodeToStats(*this);
  st.st_rdev = dev_;
  return st;
}

}  // namespace

std::shared_ptr<ISoftLink> MemCreateISoftLink(std::string_view path,
                                              ino_t inum) {
  return std::make_shared<MemISoftLink>(path, inum);
}

std::shared_ptr<Inode> MemCreateIDevice(dev_t dev, mode_t mode, ino_t inum) {
  return std::make_shared<MemIDevice>(dev, mode, inum);
}

}  // namespace junction::memfs
