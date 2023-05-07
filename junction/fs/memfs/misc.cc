// misc.cc - support for miscellaneous inode types

#include "junction/fs/dev.h"
#include "junction/fs/fs.h"

namespace junction {

namespace {

// MemISoftLink is an inode type for soft link
class MemISoftLink : public ISoftLink {
 public:
  MemISoftLink(std::string_view path, mode_t mode, ino_t inum)
      : ISoftLink(mode, inum), path_(path) {}
  ~MemISoftLink() override = default;

  Status<std::string> ReadLink() override;

 private:
  const std::string path_;
};

Status<std::string> MemISoftLink::ReadLink() { return path_; }

// MemIDevice is an inode type for character and block devices
class MemIDevice : public Inode {
 public:
  MemIDevice(dev_t dev, mode_t mode, ino_t inum)
      : Inode(mode, inum), dev_(dev) {}

  std::shared_ptr<File> Open(mode_t mode, uint32_t flags) override;

 private:
  dev_t dev_;
};

std::shared_ptr<File> MemIDevice::Open(mode_t mode, uint32_t flags) {
  return DeviceOpen(*this, dev_, mode, flags);
}

}  // namespace

std::shared_ptr<ISoftLink> MemCreateISoftLink(std::string_view path,
                                              mode_t mode, ino_t inum) {
  return std::make_shared<MemISoftLink>(path, mode, inum);
}

std::shared_ptr<Inode> MemCreateIDevice(dev_t dev, mode_t mode, ino_t inum) {
  return std::make_shared<MemISoftLink>(dev, mode, inum);
}

}  // namespace junction
