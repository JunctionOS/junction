// linuxfs.h - support for a Linux filesystem

#pragma once

extern "C" {
#include <sys/stat.h>
}

#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "junction/base/containers.h"
#include "junction/base/error.h"
#include "junction/filesystem/linuxfile.hpp"
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

  [[nodiscard]] std::string get_name() { return name_; }

  friend std::ostream& operator<<(std::ostream& os, const LinuxFileInode& node);

 private:
  const std::string name_;
  std::unordered_set<std::shared_ptr<File>>
      files_;  // files associated with this node (in the case of file type
               // inode)
  string_unordered_map<std::shared_ptr<Inode>>
      children_;  // child nodes (in the case of directory type inode)

  std::ostream& print(std::ostream& os, const uint32_t indent = 0) const;
};

class LinuxFileSystem : public FileSystem {
 public:
  LinuxFileSystem();
  virtual ~LinuxFileSystem();
  virtual Status<std::shared_ptr<File>> Open(const std::string_view& pathname,
                                     uint32_t mode, uint32_t flags) override;

  friend std::ostream& operator<<(std::ostream& os, const LinuxFileSystem& fs);

 private:
  const string_unordered_map<uint32_t>
      manifest_;  // manifest of allowed files (filepath -> flags)
};

}  // namespace junction
