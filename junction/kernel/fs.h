// fs.h - file system support

#pragma once

#include <memory>

#include "junction/kernel/file.h"

class Inode {
 public:
  virtual ~Inode() = default;
  // Create a new file for this inode.
  virtual std::shared_ptr<File> Open(uint32_t mode, uint32_t flags);
  // Lookup a child inode for this inode (can be empty).
  virtual std::shared_ptr<Inode> Lookup(const std::string_view &name);
  // Insert a new child inode into this inode (type must be directory).
  virtual void Insert(const std::string_view &name, std::shared_ptr<Inode> inode);
}

class FileSystem {
 public:

 private:
  std::shared_ptr<Inode> root_;  // the root directory of the file system
  std::shared_ptr<Inode> cwd_;   // the current working directory
};
