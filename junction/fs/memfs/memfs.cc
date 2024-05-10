// misc.cc - support for miscellaneous inode types

#include "junction/fs/memfs/memfs.h"

#include "junction/fs/memfs/memfsfile.h"

namespace junction::memfs {

namespace {

// MemISoftLink is an inode type for soft link
class MemISoftLink : public ISoftLink {
 public:
  MemISoftLink(std::string_view path)
      : ISoftLink(0, AllocateInodeNumber()), path_(path) {}
  ~MemISoftLink() override = default;

  std::string ReadLink() override { return path_; }
  Status<void> GetStats(struct stat *buf) const override {
    MemInodeToStats(*this, buf);
    return {};
  }

  Status<void> GetStatFS(struct statfs *buf) const override {
    StatFs(buf);
    return {};
  }

 private:
  const std::string path_;
};

// MemIDevice is an inode type for character and block devices
class MemIDevice : public Inode {
 public:
  MemIDevice(dev_t dev, mode_t mode)
      : Inode(mode, AllocateInodeNumber()), dev_(dev) {}

  Status<std::shared_ptr<File>> Open(uint32_t flags, mode_t mode) override {
    return DeviceOpen(*this, dev_, mode, flags);
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

 private:
  dev_t dev_;
};

}  // namespace

Status<void> MemInode::SetSize(size_t newlen) {
  if (unlikely(newlen > kMaxSizeBytes)) return MakeError(EINVAL);
  buf_.Resize(newlen);
  return {};
}

Status<void> MemInode::GetStats(struct stat *buf) const {
  MemInodeToStats(*this, buf);
  buf->st_size = buf_.size();
  buf->st_blocks = 0;
  return {};
}

Status<std::shared_ptr<File>> MemInode::Open(uint32_t flags, mode_t mode) {
  return std::make_shared<MemFSFile>(flags, mode, shared_from_base<MemInode>());
}

std::shared_ptr<ISoftLink> CreateISoftLink(std::string_view path) {
  return std::make_shared<MemISoftLink>(path);
}

std::shared_ptr<Inode> CreateIDevice(dev_t dev, mode_t mode) {
  return std::make_shared<MemIDevice>(dev, mode);
}

ino_t AllocateInodeNumber() {
  static std::atomic_size_t inos;
  return inos.fetch_add(1, std::memory_order_relaxed) + 1;
}

}  // namespace junction::memfs
