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

// Inode is the base class for all inodes
class Inode : std::enable_shared_from_this<Inode> {
 public:
  Inode(unsigned int type, unsigned long(inum)) : type_(type), inum_(inum) {}
  virtual ~Inode() = default;

  // Open a file for this inode.
  virtual std::shared_ptr<File> Open(uint32_t mode, uint32_t flags) = 0;
  // Get attributes.
  virtual Status<stat> GetAttributes() = 0;
  // Set attributes.
  virtual Status<void> SetAttributes(stat attr) = 0;

  [[nodiscard]] unsigned int get_type() const { return type_; }
  [[nodiscard]] unsigned long get_inum() const { return inum_; }

 private:
  const unsigned int type_;   // the file type referred to by this inode
  const unsigned long inum_;  // inode number
};

// ISoftLink is an inode type for soft links
class ISoftLink : public Inode {
 public:
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
  // Opens a file that supports getdents() and getdents64().
  std::shared_ptr<File> Open(uint32_t mode, uint32_t flags) override;

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
  virtual Status<void> Link(INode &node, std::string_view name) = 0;
  // Create a new normal file.
  virtual Status<std::shared_ptr<File>> Create(std::string_view name,
                                               mode_t mode) = 0;

  // If true, don't allow creation of new directory entries.
  [[nodiscard]] bool is_dead() const { return dead_; }
  // Get a reference to the parent of this directory.
  [[nodiscard]] std::shared_ptr<IDir> get_parent() const { return parent_; }

 private:
  // GetDents returns a vector of the current entries.
  virtual std::vector<dir_entry> GetDents() = 0;

  // Parent directory.
  std::shared_ptr<IDir> parent_;
  // Directory has been removed.
  bool dead_;
};

// FSRoot manages the root directory and namespace for a process
class FSRoot {
 public:
  FSRoot(std::shared_ptr<IDir> root, std::shared_ptr<IDir> cwd)
      : root_(root), cwd_(cwd) {}
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
