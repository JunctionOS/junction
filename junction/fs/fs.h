// fs.h - file system support

#pragma once

extern "C" {
#include <sys/stat.h>
#include <sys/statfs.h>
}

#include <memory>
#include <string_view>
#include <vector>

#include "junction/kernel/file.h"

namespace junction {

//
// Inode file types.
//

// Regular file.
constexpr mode_t kTypeRegularFile = S_IFREG;
// Directory.
constexpr mode_t kTypeDirectory = S_IFDIR;
// Character device.
constexpr mode_t kTypeCharacter = S_IFCHR;
// Block device.
constexpr mode_t kTypeBlock = S_IFBLK;
// Symbolic link.
constexpr mode_t kTypeSymLink = S_IFLNK;
// Pipe or FIFO.
constexpr mode_t kTypeFIFO = S_IFIFO;

// A mask of all type bits in the mode field.
constexpr mode_t kTypeMask =
    (S_IFREG | S_IFDIR | S_IFCHR | S_IFBLK | S_IFLNK | S_IFIFO);

// Inode is the base class for all inodes
class Inode : std::enable_shared_from_this<Inode> {
 public:
  Inode(mode_t mode, ino_t inum) : mode_(mode), inum_(inum) {}
  virtual ~Inode() = default;

  // Open a file for this inode.
  virtual std::shared_ptr<File> Open(mode_t mode, uint32_t flags) = 0;
  // Get attributes.
  virtual Status<struct stat> GetAttributes() = 0;
  // Set attributes.
  virtual Status<void> SetAttributes(struct stat attr) = 0;

  // permissions and other mode bits
  [[nodiscard]] mode_t get_mode() const { return mode_; }
  // the type of file
  [[nodiscard]] mode_t get_type() const { return mode_ & kTypeMask; }
  // the inode number
  [[nodiscard]] ino_t get_inum() const { return inum_; }
  // the number of hard links to the file
  [[nodiscard]] nlink_t get_nlink() const { return nlink_; }
  // increment number of hard links
  void inc_nlink() { nlink_++; }
  // decrement number of hard links
  void dec_nlink() { nlink_--; }
  // is the file fully unlinked?
  [[nodiscard]] bool is_stale() const { return nlink_ == 0; }

  // Gets a shared pointer to this inode.
  std::shared_ptr<Inode> get_this() { return shared_from_this(); };

 private:
  const mode_t mode_;  // the rype and mode
  const ino_t inum_;   // inode number
  nlink_t nlink_{1};   // number of hard links to this inode
};

// InodeToAttributes returns a partial set of attributes based on what's
// availabe in a generic inode. The caller must fill in the rest manually.
struct stat InodeToAttributes(const Inode &ino) {
  struct stat s {};
  s.st_ino = ino.get_inum();
  s.st_mode = ino.get_mode();
  s.st_nlink = ino.get_nlink();
  return s;
}

// ISoftLink is an inode type for soft links
class ISoftLink : public Inode {
 public:
  ISoftLink(mode_t mode, ino_t inum) : Inode(kTypeSymLink | mode, inum) {}
  virtual ~ISoftLink() override = default;

  // Opens a file that does nothing.
  std::shared_ptr<File> Open(uint32_t mode, uint32_t flags) override;

  // ReadLink reads the path of the link.
  virtual Status<std::string> ReadLink() = 0;
};

struct dir_entry {
  std::string name;
  unsigned long inum;
  unsigned int type;
};

// IDir is an inode type for directories
class IDir : public Inode {
 public:
  IDir(mode_t mode, ino_t inum, std::shared_ptr<IDir> parent = {})
      : Inode(kTypeDirectory | mode, inum), parent_(std::move(parent)) {}
  virtual ~IDir() override = default;

  // Opens a file that supports getdents() and getdents64().
  std::shared_ptr<File> Open(mode_t mode, uint32_t flags) override;

  // Lookup finds a directory entry by name.
  virtual Status<std::shared_ptr<Inode>> Lookup(std::string_view name) = 0;
  // MkNod creates a file (usually of a special type).
  virtual Status<void> MkNod(std::string_view name, mode_t mode, dev_t dev) = 0;
  // MkDir creates a directory.
  virtual Status<void> MkDir(std::string_view name, mode_t mode) = 0;
  // Unlink removes a file.
  virtual Status<void> Unlink(std::string_view name) = 0;
  // RmDir remove a directory.
  virtual Status<void> RmDir(std::string_view name) = 0;
  // SymLink creates a symbolic link.
  virtual Status<void> SymLink(std::string_view name,
                               std::string_view path) = 0;
  // Rename changes the name/location of a file (called on the dest IDir).
  virtual Status<void> Rename(IDir &src, std::string_view src_name,
                              std::string_view dst_name) = 0;
  // Link creates a hard link.
  virtual Status<void> Link(Inode &node, std::string_view name) = 0;
  // Create makes a new normal file.
  virtual Status<std::shared_ptr<File>> Create(std::string_view name,
                                               mode_t mode) = 0;
  // GetDents returns a vector of the current entries.
  virtual std::vector<dir_entry> GetDents() = 0;

  // Gets a shared pointer to the parent of this directory.
  [[nodiscard]] std::shared_ptr<IDir> get_parent() const { return parent_; }

  // Gets a shared pointer to this directory.
  std::shared_ptr<IDir> get_this() {
    return std::static_pointer_cast<IDir>(Inode::get_this());
  };

 private:
  // Parent directory.
  std::shared_ptr<IDir> parent_;
};

// FSRoot manages the root directory and namespace for a process
class FSRoot {
 public:
  FSRoot(std::shared_ptr<IDir> root, std::shared_ptr<IDir> cwd)
      : root_(std::move(root)), cwd_(std::move(cwd)) {}
  ~FSRoot() = default;

  [[nodiscard]] std::shared_ptr<IDir> get_root() const { return root_; }
  [[nodiscard]] std::shared_ptr<IDir> get_cwd() const { return cwd_; }

 private:
  std::shared_ptr<IDir> root_;
  std::shared_ptr<IDir> cwd_;
};

// FSLookup finds and returns a reference to the inode for a path.
Status<std::shared_ptr<Inode>> FSLookup(const FSRoot &root,
                                        std::string_view path);

}  // namespace junction
