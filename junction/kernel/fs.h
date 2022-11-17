// fs.h - file system support

#pragma once

extern "C" {
#include <sys/stat.h>
}

#include <memory>
#include <string_view>

#include "junction/kernel/file.h"

namespace junction {

//
// Inode file types.
//

// Regular file.
constexpr unsigned int kTypeRegularFile = S_IFREG;
// Directory.
constexpr unsigned int kTypeDirectory = S_IFDIR;

class Inode {
 public:
  Inode(const unsigned int type) : type_(type){};
  virtual ~Inode() = default;
  // Create a new file for this inode.
  virtual std::shared_ptr<File> Open(uint32_t mode, uint32_t flags) {
    return nullptr;
  }
  // Lookup a child inode for this inode (can be empty).
  virtual std::shared_ptr<Inode> Lookup(const std::string_view &name) {
    return nullptr;
  }
  // Insert a new child inode into this inode (must be a directory).
  virtual Status<void> Insert(const std::string_view &name,
                              std::shared_ptr<Inode> inode) {
    return MakeError(EINVAL);
  }
  // Remove a child inode from this inode (must be a directory).
  virtual Status<void> Remove(const std::string_view &name) {
    return MakeError(EINVAL);
  }
  // Adjust the size of the file.
  virtual Status<void> Truncate(size_t newlen) { return MakeError(EINVAL); }
  // Get the unix stat structure.
  virtual Status<struct stat> Stat() { return MakeError(EINVAL); }

  [[nodiscard]] unsigned int get_type() { return type_; }

 protected:
  const unsigned int type_;  // the file type referred to by this inode
};

class FileSystem {
 public:
  virtual ~FileSystem() = default;
  virtual Status<std::shared_ptr<File>> Open(const std::string_view &pathname,
                                     uint32_t mode, uint32_t flags) {
    return nullptr;
  }

 protected:
  std::shared_ptr<Inode> root_;  // the root directory of the file system
  std::shared_ptr<Inode> cwd_;   // the current working directory
};

// Sets the currently used FileSystem; used during initialization.
void set_fs(FileSystem *fs);
FileSystem *get_fs();

}  // namespace junction
