#pragma once

#include <sys/stat.h>

#include <set>

#include "junction/fs/fs.h"

namespace junction::linuxfs {

extern int linux_root_fd;
extern struct statfs linux_statfs;
extern std::set<dev_t> allowed_devs;

class LinuxInode : public Inode {
 public:
  LinuxInode(struct stat &stat, std::string &&path)
      : Inode(stat.st_mode, stat.st_ino),
        path_(std::move(path)),
        size_(stat.st_size) {
    assert(!is_symlink() && !is_dir());
  }

  // Open a file for this inode.
  Status<std::shared_ptr<File>> Open(uint32_t flags, mode_t mode) override;

  // Get attributes.
  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    buf->st_size = size_;
    buf->st_nlink = 1;
    return {};
  }

  Status<void> GetStatFS(struct statfs *buf) const override {
    *buf = linux_statfs;
    return {};
  }

  [[nodiscard]] off_t get_size() const { return size_; }

 private:
  std::string path_;
  off_t size_;
};

class LinuxISoftLink : public ISoftLink {
 public:
  LinuxISoftLink(struct stat &stat, std::string &&path, std::string_view target)
      : ISoftLink(stat.st_mode, stat.st_ino),
        path_(std::move(path)),
        target_(target) {
    assert(is_symlink());
  }

  // ReadLink reads the path of the link.
  std::string ReadLink() override { return target_; };
  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    return {};
  }

  Status<void> GetStatFS(struct statfs *buf) const override {
    *buf = linux_statfs;
    return {};
  }

 private:
  std::string path_;
  std::string target_;
};

class LinuxIDir : public IDir {
 public:
  LinuxIDir(struct stat &stat, std::string &&path, std::string_view name,
            std::shared_ptr<IDir> parent)
      : IDir(stat, name, parent), path_(std::move(path)) {
    assert(is_dir());
  }

  // Directory ops
  Status<std::shared_ptr<Inode>> Lookup(std::string_view name) override;
  Status<void> MkNod(std::string_view name, mode_t mode, dev_t dev) override {
    return MakeError(EACCES);
  }
  Status<void> MkDir(std::string_view name, mode_t mode) override {
    return MakeError(EACCES);
  }
  Status<void> Unlink(std::string_view name) override {
    return MakeError(EACCES);
  }
  Status<void> RmDir(std::string_view name) override {
    return MakeError(EACCES);
  }
  Status<void> SymLink(std::string_view name, std::string_view path) override {
    return MakeError(EACCES);
  }
  Status<void> Rename(IDir &src, std::string_view src_name,
                      std::string_view dst_name) override {
    return MakeError(EACCES);
  }
  Status<void> Link(std::string_view name,
                    std::shared_ptr<Inode> ino) override {
    return MakeError(EACCES);
  }

  Status<std::shared_ptr<File>> Create(std::string_view name, int flags,
                                       mode_t mode) override {
    return MakeError(EACCES);
  }

  std::vector<dir_entry> GetDents() override;

  // Inode ops
  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    return {};
  }

  Status<void> GetStatFS(struct statfs *buf) const override {
    *buf = linux_statfs;
    return {};
  }

 private:
  // Helper routine to intialize entries_
  Status<void> FillEntries();
  bool Initialize();

  std::string path_;
  bool initialized_{false};
};

}  // namespace junction::linuxfs
