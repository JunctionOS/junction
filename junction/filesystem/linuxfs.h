// linuxfs.h - support for a Linux filesystem

#pragma once

extern "C" {
#include <sys/stat.h>
}

#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "junction/base/containers.h"
#include "junction/base/error.h"
#include "junction/filesystem/linuxfile.h"
#include "junction/kernel/file.h"
#include "junction/kernel/fs.h"

namespace junction {

class LinuxFileInode : public Inode,
                       public std::enable_shared_from_this<Inode> {
 public:
  LinuxFileInode(const std::string_view& name, const unsigned int type);
  virtual ~LinuxFileInode();
  virtual std::shared_ptr<File> Open(uint32_t mode, uint32_t flags) override;
  virtual std::shared_ptr<Inode> Lookup(const std::string_view& name) override;
  virtual Status<void> Insert(const std::string_view& name,
                              std::shared_ptr<Inode> inode) override;
  virtual Status<void> Remove(const std::string_view& name) override;
  virtual Status<void> Truncate(size_t newlen) override;
  virtual Status<struct stat> Stat() override;

  std::shared_ptr<File> Open(const std::string_view& name, uint32_t mode,
                             uint32_t flags);
  // Walk the sub-tree starting from the given inode, searching for each
  // component of the target path. If create_missing is true, create missing
  // inodes along the path.
  static Status<std::shared_ptr<Inode>> Walk(const std::shared_ptr<Inode> start,
                                             const std::filesystem::path target,
                                             const bool create_missing);

  [[nodiscard]] std::string get_name() { return name_; }

  friend std::ostream& operator<<(std::ostream& os, const LinuxFileInode& node);

 private:
  const std::string name_;
  // file associated with this node (in the case of file type); does not keep
  // ownership, the FileTable can take a reference to this so it can manage the
  // file's lifetime
  std::weak_ptr<File> file_;
  // child nodes (in the case of directory type inode)
  string_unordered_map<std::shared_ptr<Inode>> children_;

  std::ostream& print(std::ostream& os, const uint32_t indent = 0) const;
};

class LinuxFileSystemManifest {
 public:
  void Insert(const std::string path, const uint32_t flags);
  void Remove(const std::string_view path);
  [[nodiscard]] bool Exists(const std::string_view path) const;

 private:
  // list of allowed files (filepath -> flags)
  string_unordered_map<uint32_t> files_;
  // list of wildcard paths (path -> flags)
  string_unordered_map<uint32_t> wildcards_;
};

class LinuxFileSystem : public FileSystem {
 public:
  LinuxFileSystem();
  LinuxFileSystem(
      const std::shared_ptr<const LinuxFileSystemManifest> manifest);
  virtual ~LinuxFileSystem();
  virtual Status<std::shared_ptr<File>> Open(const std::string_view& pathname,
                                             uint32_t mode,
                                             uint32_t flags) override;

  friend std::ostream& operator<<(std::ostream& os, const LinuxFileSystem& fs);

 private:
  std::shared_ptr<const LinuxFileSystemManifest> manifest_;
};

}  // namespace junction
