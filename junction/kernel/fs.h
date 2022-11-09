// fs.h - file system support

#pragma once

extern "C" {
#include <sys/stat.h>
}

#include <memory>
#include <string_view>
#include <vector>

#include "junction/kernel/file.h"

namespace junction {

class Inode {
 public:
  virtual ~Inode() = default;
  // Create a new file for this inode.
  virtual std::shared_ptr<File> Open(uint32_t mode, uint32_t flags);
  // Lookup a child inode for this inode (can be empty).
  virtual std::shared_ptr<Inode> Lookup(const std::string_view &name);
  // Insert a new child inode into this inode (must be a directory).
  virtual Status<void> Insert(const std::string_view &name,
                              std::shared_ptr<Inode> inode);
  // Remove a child inode from this inode (must be a directory).
  virtual Status<void> Remove(const std::string_view &name);
  // Adjust the size of the file.
  virtual Status<void> Truncate(size_t newlen);
  // Get the unix stat structure.
  virtual Status<stat> Stat();
}

class FileSystem {
 public:
 private:
  std::shared_ptr<Inode> root_;  // the root directory of the file system
  std::shared_ptr<Inode> cwd_;   // the current working directory
};

}  // namespace junction
