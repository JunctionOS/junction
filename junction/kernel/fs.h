// fs.h - file system support

#pragma once

extern "C" {
#include <sys/stat.h>
#include <sys/statfs.h>
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
// Character device.
constexpr unsigned int kTypeCharacter = S_IFCHR;
// Block device.
constexpr unsigned int kTypeBlock = S_IFBLK;
// Symbolic link.
constexpr unsigned int kTypeSymLink = S_IFLNK;
// Pipe or FIFO.
constexpr unsigned int kTypeFIFO = S_IFIFO;

#if 0
//
// TODO: These are notes on a new file system design (WIP)
//

class Inode : std::enable_shared_from_this<Inode> {
 public:
  Inode(unsigned int type, unsigned long (inum) : type_(type), inum_(inum) {}
  virtual ~Inode() = default;

  // Open a file for this inode.
  virtual std::shared_ptr<File> Open(uint32_t mode, uint32_t flags) = 0;

  [[nodiscard]] unsigned int get_type() const {
    return type_; }
  [[nodiscard]] unsigned long get_inode_number() const {
    return inum_; }

 private:
  const unsigned int type_;   // the file type referred to by this inode
  const unsigned long inum_;  // inode number
};

struct dir_entry {
  std::string name;
  unsigned long inum;
  unsigned int type;
};

class IDir : public Inode {
 public:
  // Opens a file that supports getdents64().
  std::shared_ptr<File> Open(uint32_t mode, uint32_t flags) override;

  // Lookup an inode in this directory (can be empty).
  virtual std::shared_ptr<Inode> Lookup(std::string_view name) = 0;
  // Insert an inode into this directory.
  virtual Status<void> Insert(std::string_view name,
                              std::shared_ptr<Inode> inode) = 0;
  // Remove an inode from this directory.
  virtual Status<void> Remove(std::string_view name) = 0;
  // Create a new directory.
  virtual Status<void> MakeDir(std::string_view name, uint32_t mode) = 0;
  // Create a new file.
  virtual Status<std::shared_ptr<File>> Create(std::string_view name,
                                               uint32_t mode) = 0;

 private:
  // GetDents returns a vector of the current entries.
  virtual std::vector<dir_entry> GetDents() = 0;
};

class FileSystem {
 private:
  std::shared_ptr<IDir> root_;
  std::shared_ptr<IDir> cwd_;
};

#endif

class Inode {
 public:
  Inode(unsigned int type, unsigned int ino) : type_(type), ino_(ino){};
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
  virtual Status<void> Truncate(off_t newlen) { return MakeError(EINVAL); }
  // Manipulate the allocated disk space for the file.
  virtual Status<void> Allocate(int mode, off_t offset, off_t len) {
    return MakeError(EINVAL);
  }
  // Get the UNIX stat structure.
  virtual Status<void> Stat(struct stat *buf) { return MakeError(EINVAL); }
  virtual Status<size_t> Read(std::span<std::byte> buf, off_t off) {
    return MakeError(EINVAL);
  }
  virtual Status<size_t> Write(std::span<const std::byte> buf, off_t off) {
    return MakeError(EINVAL);
  }

  [[nodiscard]] unsigned int get_type() { return type_; }
  [[nodiscard]] unsigned long get_ino() { return ino_; }

 protected:
  const unsigned int type_;  // the file type referred to by this inode
  const unsigned long ino_;  // inode number
};

class FileSystem {
 public:
  virtual ~FileSystem() = default;
  virtual Status<std::shared_ptr<File>> Open(const std::string_view &pathname,
                                             uint32_t mode, uint32_t flags) {
    return MakeError(EINVAL);
  }
  virtual Status<void> CreateDirectory(const std::string_view &pathname,
                                       uint32_t mode) {
    return MakeError(EINVAL);
  }
  virtual Status<void> RemoveDirectory(const std::string_view &pathname) {
    return MakeError(EINVAL);
  }
  virtual Status<void> StatFS(const std::string_view &pathname,
                              struct statfs *buf) {
    return MakeError(EINVAL);
  }
  virtual Status<void> Stat(const std::string_view &pathname,
                            struct stat *buf) {
    return MakeError(EINVAL);
  }
  virtual Status<void> Link(const std::string_view &oldpath,
                            const std::string_view &newpath) {
    return MakeError(EINVAL);
  }
  virtual Status<void> Unlink(const std::string_view &pathname) {
    return MakeError(EINVAL);
  }

  // Returns true if the given pathname is supported by the file system.
  // e.g., it may check if a particular prefix can be handled by the file
  // system or not.
  virtual bool is_supported(const std::string_view &pathname, uint32_t mode,
                            uint32_t flags) {
    return false;
  }

  virtual mode_t get_umask() { return 0; }
  virtual void set_umask(mode_t umask) { return; }
};

// Currently in-use file system.
extern std::unique_ptr<FileSystem> fs_;

// Use the provided file system and perform initialization steps.
void init_fs(FileSystem *fs);

// Get the currently in-use file system.
inline FileSystem *get_fs() { return fs_.get(); }

}  // namespace junction
