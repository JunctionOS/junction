// fs.h - file system support

#pragma once

extern "C" {
#include <sys/stat.h>
#include <sys/statfs.h>
}

#include <atomic>
#include <map>
#include <memory>
#include <string_view>
#include <vector>

#include "junction/bindings/rcu.h"
#include "junction/fs/file.h"

namespace junction {

//
// Inode file types.
//

// Regular file.
inline constexpr mode_t kTypeRegularFile = S_IFREG;
// Directory.
inline constexpr mode_t kTypeDirectory = S_IFDIR;
// Character device.
inline constexpr mode_t kTypeCharacter = S_IFCHR;
// Block device.
inline constexpr mode_t kTypeBlock = S_IFBLK;
// Symbolic link.
inline constexpr mode_t kTypeSymLink = S_IFLNK;
// Pipe or FIFO.
inline constexpr mode_t kTypeFIFO = S_IFIFO;

// A mask of all type bits in the mode field.
inline constexpr mode_t kTypeMask =
    (S_IFREG | S_IFDIR | S_IFCHR | S_IFBLK | S_IFLNK | S_IFIFO);

// Shift required to convert type bits to file types (eg DT_REG, etc.)
inline constexpr uint32_t kTypeShift = 12;

// Inode is the base class for all inodes
class Inode : public std::enable_shared_from_this<Inode> {
 public:
  Inode(mode_t mode, ino_t inum) : mode_(mode), inum_(inum) {}

  virtual ~Inode() = default;

  // Open a file for this inode.
  virtual Status<std::shared_ptr<File>> Open(uint32_t flags, mode_t mode) = 0;
  // Get attributes.
  virtual Status<void> GetStats(struct stat *buf) const = 0;
  // Get attributes about this Inode's filesystem.
  virtual Status<void> GetStatFS(struct statfs *buf) const {
    return MakeError(ENOSYS);
  }
  // Sets the size of this inode.
  virtual Status<void> SetSize(size_t sz) { return MakeError(EINVAL); }

  // permissions and other mode bits
  [[nodiscard]] mode_t get_mode() const { return mode_; }
  // the type of file
  [[nodiscard]] mode_t get_type() const { return get_mode() & kTypeMask; }
  // Is this inode a directory?
  [[nodiscard]] bool is_dir() const { return get_type() == kTypeDirectory; }
  // Is this inode a symlink?
  [[nodiscard]] bool is_symlink() const { return get_type() == kTypeSymLink; }
  // Is this inode a regular file?
  [[nodiscard]] bool is_regular() const {
    return get_type() == kTypeRegularFile;
  }
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
  [[nodiscard]] std::shared_ptr<Inode> get_this() {
    return shared_from_this();
  };

 protected:
  template <class Derived>
  [[nodiscard]] std::shared_ptr<Derived> shared_from_base() {
    return std::static_pointer_cast<Derived>(shared_from_this());
  }

 private:
  const mode_t mode_;              // the type and mode
  const ino_t inum_;               // inode number
  std::atomic<nlink_t> nlink_{0};  // number of hard links to this inode
};

// InodeToStats returns a partial set of attributes based on what's availabe in
// a generic inode. The caller must fill in the rest manually.
inline void InodeToStats(const Inode &ino, struct stat *buf) {
  memset(buf, 0, sizeof(*buf));
  buf->st_ino = ino.get_inum();
  buf->st_mode = ino.get_mode();
  buf->st_nlink = ino.get_nlink();
}

// ISoftLink is an inode type for soft links
class ISoftLink : public Inode {
 public:
  ISoftLink(mode_t mode, ino_t inum) : Inode(kTypeSymLink | mode, inum) {}
  ~ISoftLink() override = default;

  // Opens a file that does nothing.
  Status<std::shared_ptr<File>> Open(uint32_t flags, mode_t mode) override {
    return std::make_shared<SoftLinkFile>(flags, mode, get_this());
  }

  // ReadLink reads the path of the link.
  virtual std::string ReadLink() = 0;

  // Gets a shared pointer to this softlink.
  [[nodiscard]] std::shared_ptr<ISoftLink> get_this() {
    return std::static_pointer_cast<ISoftLink>(Inode::get_this());
  };
};

struct dir_entry {
  std::string name;
  unsigned long inum;
  unsigned int type;
};

// Backwards link for an IDir; contains a pointer to the parent and the name
// of this IDir.
struct ParentPointer : public rt::RCUObject {
  ParentPointer(std::shared_ptr<IDir> parent, std::string &&name)
      : parent(std::move(parent)), name_in_parent(std::move(name)) {}
  ParentPointer(std::shared_ptr<IDir> parent, std::string_view name)
      : parent(std::move(parent)), name_in_parent(name) {}
  std::shared_ptr<IDir> parent;
  std::string name_in_parent;
};

// Forward declaration.
class FSRoot;

// IDir is an inode type for directories
class IDir : public Inode {
 public:
  IDir(mode_t mode, ino_t inum, std::string_view name,
       std::shared_ptr<IDir> parent = {})
      : Inode(kTypeDirectory | mode, inum),
        pptr_(std::make_unique<ParentPointer>(std::move(parent), name)),
        rcup_(pptr_.get()) {}
  IDir(const struct stat &buf, std::string_view name,
       std::shared_ptr<IDir> parent = {})
      : Inode(kTypeDirectory | buf.st_mode, buf.st_ino),
        pptr_(std::make_unique<ParentPointer>(std::move(parent), name)),
        rcup_(pptr_.get()) {}

  ~IDir() override = default;

  // Opens a file that supports getdents() and getdents64().
  Status<std::shared_ptr<File>> Open(uint32_t flags, mode_t mode) override {
    return std::make_shared<DirectoryFile>(flags, mode, get_this());
  }

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
                               std::string_view target) = 0;
  // Rename changes the name/location of a file (called on the dest IDir).
  virtual Status<void> Rename(IDir &src, std::string_view src_name,
                              std::string_view dst_name, bool replace) = 0;
  // Link creates a hard link.
  virtual Status<void> Link(std::string_view name,
                            std::shared_ptr<Inode> ino) = 0;
  // Create makes a new normal file.
  virtual Status<std::shared_ptr<File>> Create(std::string_view name, int flags,
                                               mode_t mode) = 0;
  // GetDents returns a vector of the current entries.
  virtual std::vector<dir_entry> GetDents() = 0;

  virtual Status<void> GetStats(struct stat *buf) const override = 0;

  // Gets a shared pointer to the parent of this directory.
  [[nodiscard]] std::shared_ptr<IDir> get_parent() const {
    rt::RCURead l;
    rt::RCUReadGuard g(l);
    return rcup_.get()->parent;
  }

  [[nodiscard]] std::string get_name() const {
    rt::RCURead l;
    rt::RCUReadGuard g(l);
    return rcup_.get()->name_in_parent;
  }

  [[nodiscard]] ParentPointer get_parent_info() const {
    rt::RCURead l;
    rt::RCUReadGuard g(l);
    return *rcup_.get();
  }

  // Gets a shared pointer to this directory.
  [[nodiscard]] std::shared_ptr<IDir> get_this() {
    return std::static_pointer_cast<IDir>(Inode::get_this());
  };

  // Fills @dst with the full path of this IDir.
  Status<std::span<char>> GetFullPath(const FSRoot &fs, std::span<char> dst);

  // Must be called during a rename.
  void SetParent(std::shared_ptr<IDir> new_parent, std::string_view new_name) {
    assert(!lock_.IsHeld());
    rt::MutexGuard g(lock_);
    rt::RCURead l;
    rt::RCUReadGuard rg(l);
    auto newp =
        std::make_unique<ParentPointer>(std::move(new_parent), new_name);
    rcup_.set(newp.get());
    rt::RCUFree(std::move(pptr_));
    pptr_ = std::move(newp);
  }

  // Directly inserts this ino into the entries list.
  void Mount(std::string name, std::shared_ptr<Inode> ino) {
    rt::MutexGuard g(lock_);
    InsertLockedNoCheck(name, ino);
    if (ino->is_dir()) {
      IDir &dir = static_cast<IDir &>(*ino);
      dir.SetParent(get_this(), name);
    }
  }

 protected:
  rt::Mutex lock_;
  std::map<std::string, std::shared_ptr<Inode>, std::less<>> entries_;

  void InsertLockedNoCheck(std::string_view name, std::shared_ptr<Inode> ino) {
    assert(lock_.IsHeld());
    ino->inc_nlink();
    entries_.emplace(name, std::move(ino));
  }

  [[nodiscard]] Status<void> InsertLocked(std::string name,
                                          std::shared_ptr<Inode> ino) {
    assert(lock_.IsHeld());
    auto [it, okay] = entries_.try_emplace(std::move(name), std::move(ino));
    if (!okay) return MakeError(EEXIST);
    it->second->inc_nlink();
    return {};
  }

  [[nodiscard]] Status<void> Insert(std::string name,
                                    std::shared_ptr<Inode> ino) {
    rt::MutexGuard g(lock_);
    return InsertLocked(std::move(name), std::move(ino));
  }

 private:
  std::unique_ptr<ParentPointer> pptr_;
  rt::RCUPtr<ParentPointer> rcup_;
};

// FSRoot manages the root directory and namespace for a process
class FSRoot {
 public:
  FSRoot(std::shared_ptr<IDir> root, std::shared_ptr<IDir> cwd)
      : root_(std::move(root)), cwd_(std::move(cwd)), cwd_rcup_(cwd_.get()) {}
  ~FSRoot() = default;

  FSRoot(const FSRoot &other)
      : root_(other.root_),
        cwd_(other.get_cwd()),
        cwd_rcup_(cwd_.get()),
        umask_(other.umask_) {}

  [[nodiscard]] std::shared_ptr<IDir> get_root() const { return root_; }
  [[nodiscard]] std::shared_ptr<IDir> get_cwd() const {
    rt::RCURead l;
    rt::RCUReadGuard g(l);
    const IDir *dir = cwd_rcup_.get();
    return const_cast<IDir *>(dir)->get_this();
  }
  [[nodiscard]] static FSRoot &GetGlobalRoot() { return *global_root_; }
  [[nodiscard]] mode_t get_umask() const { return umask_; }

  // Caller must synchronize this call with a lock.
  void SetCwd(std::shared_ptr<IDir> new_cwd) {
    cwd_rcup_.set(new_cwd.get());
    rt::RCUFree(std::move(cwd_));
    cwd_ = std::move(new_cwd);
  }

  mode_t SetUmask(mode_t umask) {
    mode_t prev = umask_;
    umask_ = umask & 0777;
    return prev;
  }

  static void InitFsRoot(std::shared_ptr<IDir> root) {
    assert(!global_root_);
    global_root_ = new FSRoot(root, root);
  }

 private:
  std::shared_ptr<IDir> root_;
  std::shared_ptr<IDir> cwd_;
  rt::RCUPtr<IDir> cwd_rcup_;
  mode_t umask_{0};
  static FSRoot *global_root_;
};

namespace linuxfs {
Status<std::shared_ptr<IDir>> MountLinux(std::string_view path);
Status<std::shared_ptr<IDir>> InitLinuxRoot();
}  // namespace linuxfs

namespace memfs {
std::shared_ptr<IDir> MkFolder();
}

Status<void> InitFs(
    const std::vector<std::pair<std::string, std::string>> &linux_mount_points,
    const std::vector<std::string> &mem_mount_points);

// Allocate a unique inode number.
ino_t AllocateInodeNumber();

class Process;

// LookupInode finds an inode for a path
Status<std::shared_ptr<Inode>> LookupInode(const FSRoot &fs,
                                           std::string_view path,
                                           bool chase_link = true);

// LookupInode finds an inode for a path
Status<std::shared_ptr<Inode>> LookupInode(Process &p, int dirfd,
                                           std::string_view path,
                                           bool chase_link = true);

}  // namespace junction
