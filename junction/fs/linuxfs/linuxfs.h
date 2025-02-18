#pragma once

#include <sys/stat.h>

#include <set>

#include "junction/fs/fs.h"
#include "junction/fs/memfs/memfs.h"
#include "junction/kernel/ksys.h"
#include "junction/snapshot/cereal.h"

namespace junction::linuxfs {

extern KernelFile linux_root_fd;
extern struct statfs linux_statfs;
extern std::set<dev_t> allowed_devs;

__noinline void LinuxFSPanic(std::string_view msg, Error err);

class LinuxISoftLink : public memfs::MemISoftLink {
 public:
  LinuxISoftLink(const struct stat &stat, std::string path)
      : MemISoftLink(stat, std::move(path)) {}
  LinuxISoftLink(ino_t ino, std::string path)
      : MemISoftLink(std::move(path), ino) {}
  bool SnapshotPrunable() override { return true; }
};

class LinuxInode : public Inode {
 public:
  LinuxInode(const struct stat &stat, std::string path)
      : Inode(stat.st_mode, stat.st_ino),
        path_(std::move(path)),
        size_(stat.st_size),
        mtime_(stat.st_mtime),
        dev_(stat.st_dev) {
    // TODO: switch to assert after finding the bug causing this check to file
    // for LinuxIDirs.
    if (is_symlink() || is_dir()) {
      LOG(ERR)
          << "attempting to instantiate linux inode with folder/symlink: path "
          << path_;
      syscall_exit(-1);
    }
  }

  // Open a file for this inode.
  Status<std::shared_ptr<File>> Open(
      uint32_t flags, FileMode mode,
      std::shared_ptr<DirectoryEntry> dent) override;

  bool SnapshotPrunable() override { return true; }

  // Get attributes.
  Status<void> GetStats(struct stat *buf) const override {
    InodeToStats(*this, buf);
    buf->st_size = get_size();
    buf->st_nlink = 1;
    buf->st_mtime = mtime_;
    buf->st_dev = dev_;
    return {};
  }

  Status<void> GetStatFS(struct statfs *buf) const override {
    *buf = linux_statfs;
    return {};
  }

  [[nodiscard]] off_t get_size() const;
  [[nodiscard]] std::string_view get_path() const { return path_; }
  [[nodiscard]] Status<void> SetSize(size_t sz) override;

 private:
  const std::string path_;
  const off_t size_;
  const time_t mtime_;
  const dev_t dev_;
};

class LinuxIDir : public memfs::MemIDir {
 public:
  LinuxIDir(Token t, const struct stat &stat, std::string path)
      : MemIDir(t, stat), path_(std::move(path)) {
    // TODO: switch to assert after finding the bug triggering this.
    if (!is_dir()) {
      LOG(ERR) << "attempting to instantiate linuxidir with non-dir " << path_;
      syscall_exit(-1);
    }
  }

  bool SnapshotPrunable() override { return true; }
  bool SnapshotRecurse() override { return path_ != "/tmp"; }

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
  // Helper routine to intialize entries_.
  Status<void> FillEntries();
  void DoInitialize() override;

  Status<DirectoryEntry *> AddInode(const struct stat &stat,
                                    std::string abspath,
                                    std::string_view entry_name);

  virtual DirectoryEntry *InstantiateChildDir(const struct stat &buf,
                                              std::string abspath,
                                              std::string name) {
    assert_locked();
    return AddIDirLockedNoCheck<LinuxIDir>(std::move(name), buf,
                                           std::move(abspath));
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
};

class LinuxWrIDir : public LinuxIDir {
 public:
  LinuxWrIDir(Token t, const struct stat &stat, std::string path)
      : LinuxIDir(t, stat, std::move(path)) {
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
  DirectoryEntry *InstantiateChildDir(const struct stat &buf,
                                      std::string abspath,
                                      std::string name) override {
    assert_locked();
    return AddIDirLockedNoCheck<LinuxWrIDir>(std::move(name), buf,
                                             std::move(abspath));
  }

 private:
  // Helper routine for renaming.
  Status<void> DoRename(LinuxWrIDir &src, std::string_view src_name,
                        std::string_view dst_name, bool replace);
};

}  // namespace junction::linuxfs
