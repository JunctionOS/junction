#pragma once

#include <sys/stat.h>

#include <set>

#include "junction/fs/fs.h"
#include "junction/fs/memfs/memfs.h"
#include "junction/kernel/ksys.h"

namespace junction::linuxfs {

extern KernelFile linux_root_fd;
extern struct statfs linux_statfs;
extern std::set<dev_t> allowed_devs;

class LinuxInode : public Inode {
 public:
  LinuxInode(const struct stat &stat, std::string &&path)
      : Inode(stat.st_mode, stat.st_ino),
        path_(std::move(path)),
        size_(stat.st_size) {
    assert(!is_symlink() && !is_dir());
  }

  // Open a file for this inode.
  Status<std::shared_ptr<File>> Open(uint32_t flags, FileMode mode) override;

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
  [[nodiscard]] std::string_view get_path() const { return path_; }

 private:
  const std::string path_;
  const off_t size_;
};

class LinuxIDir : public memfs::MemIDir {
 public:
  LinuxIDir(const struct stat &stat, std::string &&path, std::string_view name,
            std::shared_ptr<IDir> parent)
      : MemIDir(stat, std::string(name), std::move(parent)),
        path_(std::move(path)) {
    assert(is_dir());
  }

  // Directory ops
  Status<std::shared_ptr<Inode>> Lookup(std::string_view name) override {
    InitCheck();
    return MemIDir::Lookup(name);
  }
  Status<void> MkNod(std::string_view name, mode_t mode, dev_t dev) override {
    InitCheck();
    return MemIDir::MkNod(name, mode, dev);
  }
  Status<void> MkDir(std::string_view name, mode_t mode) override {
    InitCheck();
    return MemIDir::MkDir(name, mode);
  }
  Status<void> Unlink(std::string_view name) override {
    InitCheck();
    return MemIDir::Unlink(name);
  }
  Status<void> RmDir(std::string_view name) override {
    InitCheck();
    return MemIDir::RmDir(name);
  }
  Status<void> SymLink(std::string_view name,
                       std::string_view target) override {
    InitCheck();
    return MemIDir::SymLink(name, target);
  }

  Status<void> Rename(IDir &src, std::string_view src_name,
                      std::string_view dst_name, bool replace) override {
    InitCheck();
    return MemIDir::Rename(src, src_name, dst_name, replace);
  }

  Status<void> Link(std::string_view name,
                    std::shared_ptr<Inode> ino) override {
    InitCheck();
    return MemIDir::Link(name, std::move(ino));
  }

  Status<std::shared_ptr<File>> Create(std::string_view name, int flags,
                                       mode_t mode, FileMode fmode) override {
    InitCheck();
    return MemIDir::Create(name, flags, mode, fmode);
  }

  std::vector<dir_entry> GetDents() override {
    InitCheck();
    return MemIDir::GetDents();
  }

  // Inode ops
  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    return {};
  }

  Status<void> GetStatFS(struct statfs *buf) const override {
    *buf = linux_statfs;
    return {};
  }

 protected:
  // Helper routine to intialize entries_
  Status<void> FillEntries();
  void Initialize();

  Status<std::shared_ptr<Inode>> ToInode(const struct stat &stat,
                                         std::string &&abspath,
                                         std::string_view entry_name);

  virtual std::shared_ptr<IDir> InstantiateChildDir(const struct stat &buf,
                                                    std::string &&abspath,
                                                    std::string_view name) {
    return std::make_shared<LinuxIDir>(buf, std::move(abspath), name,
                                       get_this());
  }

  void InitCheck() {
    if (access_once(initialized_)) return;
    rt::MutexGuard g(lock_);
    if (!initialized_) Initialize();
  }

  Status<KernelFile> GetLinuxDirFD() const {
    return linux_root_fd.OpenAt(path_, O_DIRECTORY, FileMode::kRead);
  }

  inline std::string AppendFileName(std::string_view name) const {
    std::string result;
    result.reserve(path_.size() + 1 + name.size());
    result.append(path_);
    result.append("/");
    result.append(name);
    return result;
  }

  const std::string path_;
  bool initialized_{false};
};

class LinuxWrIDir : public LinuxIDir {
 public:
  LinuxWrIDir(const struct stat &stat, std::string &&path,
              std::string_view name, std::shared_ptr<IDir> parent)
      : LinuxIDir(stat, std::move(path), name, std::move(parent)) {
    assert(is_dir());
  }

  // Directory ops
  Status<void> MkNod(std::string_view name, mode_t mode, dev_t dev) override {
    return MakeError(EACCES);
  }

  Status<void> MkDir(std::string_view name, mode_t mode) override;
  Status<void> Unlink(std::string_view name) override;
  Status<void> RmDir(std::string_view name) override;
  Status<void> SymLink(std::string_view name, std::string_view target) override;
  Status<void> Rename(IDir &src, std::string_view src_name,
                      std::string_view dst_name, bool replace) override;
  Status<void> Link(std::string_view name, std::shared_ptr<Inode> ino) override;
  Status<std::shared_ptr<File>> Create(std::string_view name, int flags,
                                       mode_t mode, FileMode fmode) override;

 protected:
  std::shared_ptr<IDir> InstantiateChildDir(const struct stat &buf,
                                            std::string &&abspath,
                                            std::string_view name) override {
    return std::make_shared<LinuxWrIDir>(buf, std::move(abspath), name,
                                         get_this());
  }

 private:
  // Helper routine for renaming.
  Status<void> DoRename(LinuxWrIDir &src, std::string_view src_name,
                        std::string_view dst_name, bool replace);
};

}  // namespace junction::linuxfs
