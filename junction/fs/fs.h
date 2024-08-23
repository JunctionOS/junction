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

#include "junction/base/intrusive.h"
#include "junction/fs/file.h"
#include "junction/snapshot/cereal.h"

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

class File;
class SoftLinkFile;

// Inode is the base class for all inodes
class Inode : public std::enable_shared_from_this<Inode> {
 public:
  Inode(mode_t mode, ino_t inum) : mode_(mode), inum_(inum) {}

  virtual ~Inode() = default;

  // Open a file for this inode.
  virtual Status<std::shared_ptr<File>> Open(
      uint32_t flags, FileMode fmode, std::shared_ptr<DirectoryEntry> dent) = 0;
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

  template <class Archive>
  void save(Archive &ar) const {
    ar(nlink_);
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(nlink_);
  }

  // True if this inode can be dropped during snapshotting.
  virtual bool SnapshotPrunable() { return false; }

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
  ISoftLink(const struct stat &buf)
      : Inode(kTypeSymLink | buf.st_mode, buf.st_ino) {}

  ~ISoftLink() override = default;

  // Opens a file that does nothing.
  Status<std::shared_ptr<File>> Open(
      uint32_t flags, FileMode fmode,
      std::shared_ptr<DirectoryEntry> dent) override;

  // ReadLink reads the path of the link.
  virtual std::string ReadLink() const = 0;

  // Gets a shared pointer to this softlink.
  [[nodiscard]] std::shared_ptr<ISoftLink> get_this() {
    return std::static_pointer_cast<ISoftLink>(Inode::get_this());
  };

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<Inode>(this));
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(cereal::base_class<Inode>(this));
  }
};

struct dir_entry {
  std::string name;
  unsigned long inum;
  unsigned int type;
};

// Forward declaration.
class FSRoot;

template <typename T>
class DentryMap;

class DirectoryEntry : public std::enable_shared_from_this<DirectoryEntry> {
 public:
  DirectoryEntry(std::string name, std::shared_ptr<DirectoryEntry> parent,
                 std::shared_ptr<Inode> entry)
      : name_(std::move(name)),
        inode_(std::move(entry)),
        parent_(std::move(parent)) {
    if (parent_.load(std::memory_order_relaxed)) inode_->inc_nlink();
  }

  ~DirectoryEntry() { DecLink(); }

  Status<std::shared_ptr<File>> Open(uint32_t flags, FileMode fmode) {
    return get_inode_ref().Open(flags, fmode, shared_from_this());
  }

  // Place the full path of this entry into os.
  [[nodiscard]] Status<void> GetFullPath(std::ostream &os);

  // Get the full pathname to this directory entry in a string. This slower
  // variant should be used outside of performance critical sections.
  [[nodiscard]] Status<std::string> GetPathStr() {
    std::stringstream ss;
    if (Status<void> ret = GetFullPath(ss); !ret) return MakeError(ret);
    return ss.str();
  }

  // Caller must hold the lock of the parent directory.
  dir_entry entry_info() const {
    return {name_, inode_->get_inum(), inode_->get_type()};
  }

  // Get the Inode that this entry points to.
  [[nodiscard]] std::shared_ptr<Inode> get_inode() const { return inode_; }
  [[nodiscard]] Inode &get_inode_ref() { return *inode_; }

  // Get the current name.
  [[nodiscard]] std::string get_name() {
    rt::SpinGuard g(lock_);
    return name_;
  }
  // Get the current name. This variant can be called if the name won't be
  // change while the call is happening.
  [[nodiscard]] std::string_view get_name_locked() const { return name_; }
  // Get the parent directory entry.
  [[nodiscard]] std::shared_ptr<DirectoryEntry> get_parent_ent() const {
    return parent_.load(std::memory_order_acquire);
  }
  // Get the parent directory entry. This variant can be called if the parent
  // won't change during the call.
  [[nodiscard]] DirectoryEntry &get_parent_ent_locked() const {
    return *parent_.load(std::memory_order_relaxed).get();
  }
  // Get the parent directory.
  [[nodiscard]] Status<std::shared_ptr<IDir>> get_parent_dir() const {
    std::shared_ptr<DirectoryEntry> p = parent_.load(std::memory_order_acquire);
    if (!p) return MakeError(ESTALE);
    return fast_pointer_cast<IDir>(p->get_inode());
  }
  // Get the parent directory. This variant can be called if the parent won't
  // change during the call.
  [[nodiscard]] IDir &get_parent_dir_locked() const;

  [[nodiscard]] std::pair<std::string, std::shared_ptr<DirectoryEntry>>
  get_info() {
    rt::SpinGuard g(lock_);
    return {name_, parent_.load(std::memory_order_relaxed)};
  }

  void SetRootEntry() {
    assert(parent_.load() == nullptr && name_.size() == 0);
    parent_.store(shared_from_this(), std::memory_order_relaxed);
    name_ = ".";
    inode_->inc_nlink();
  }

  void Invalidate() {
    // May be called with directory locks held.
    assert(parent_.load(std::memory_order_relaxed));
    DecLink();
    parent_ = {};
  }

  IntrusiveSetNode node;
  // DentryMap's reference to this dentry.
  std::shared_ptr<DirectoryEntry> intrusive_ref_;

  bool operator<(const DirectoryEntry &other) const {
    return name_ < other.name_;
  }

  void save(cereal::BinaryOutputArchive &ar) const;

  static void load_and_construct(cereal::BinaryInputArchive &ar,
                                 cereal::construct<DirectoryEntry> &construct);

  // True if this directory entry points to an inode that will be serialized.
  [[nodiscard]] bool WillBeSerialized();

 private:
  friend class DentryMap<IDir>;
  rt::Spin lock_;
  std::string name_;
  const std::shared_ptr<Inode> inode_;
  std::atomic<std::shared_ptr<DirectoryEntry>> parent_;

  void DecLink() {
    if (!parent_.load(std::memory_order_relaxed)) return;
    inode_->dec_nlink();
    if (inode_->is_dir()) assert(inode_->is_stale());
  }
};

// A per-IDir map of directory entries.
// https://en.wikipedia.org/wiki/Curiously_recurring_template_pattern
template <typename T>
class DentryMap {
  using DentSet = IntrusiveSet<DirectoryEntry, &DirectoryEntry::node>;

 public:
  DentryMap() = default;

  [[nodiscard]] Status<void> Insert(std::shared_ptr<DirectoryEntry> sp) {
    assert_locked();
    assert(!linked_in_set(sp.get()));
    DirectoryEntry *ent = sp.get();
    DentSet::insert_commit_data commit_data;
    auto [_it, success] = dents_.insert_check(*ent, commit_data);
    if (!success) return MakeError(EEXIST);
    ent->intrusive_ref_ = std::move(sp);
    dents_.insert_commit(*ent, commit_data);
    return {};
  }

  void InsertOverwrite(std::shared_ptr<DirectoryEntry> sp) {
    assert_locked();
    assert(!linked_in_set(sp.get()));
    DirectoryEntry *ent = sp.get();
    DentSet::insert_commit_data commit_data;
    auto [conflict, success] = dents_.insert_check(*ent, commit_data);
    if (!success) {
      UnlinkAndDispose(&*conflict);
      dents_.insert(*ent);
    } else {
      dents_.insert_commit(*ent, commit_data);
    }
    ent->intrusive_ref_ = std::move(sp);
  }

  void UnlinkAndDispose(DirectoryEntry *sp);
  Status<void> UnlinkAndDispose(std::string_view name) {
    assert_locked();
    auto it = dents_.find(name, StrViewComp());
    if (it == dents_.end()) return MakeError(ENOENT);
    UnlinkAndDispose(&*it);
    return {};
  }

  [[nodiscard]] size_t size() const { return dents_.size(); }

  [[nodiscard]] Status<void> MoveFrom(DentryMap &src, std::string_view src_name,
                                      std::string_view dst_name,
                                      bool overwrite) {
    assert_locked();
    assert(src.getdir().lock_.IsHeld());

    auto src_it = src.dents_.find(src_name, StrViewComp());
    if (src_it == src.dents_.end()) return MakeError(ENOENT);

    DirectoryEntry *dent = &*src_it;

    // Remove the entry before checking for conlicts so we don't destroy it if
    // the rename src/dst are equal.
    src.dents_.erase(src_it);

    // Check for conflict at new location.
    DentSet::insert_commit_data commit_data;
    auto [conflict, success] =
        dents_.insert_check(dst_name, StrViewComp(), commit_data);
    if (!success) {
      if (!overwrite) {
        src.dents_.insert(*dent);
        return MakeError(EEXIST);
      }
      UnlinkAndDispose(&*conflict);
      // redo the insert check so it doesn't need to be done while the spin lock
      // is held.
      auto [conflict, success] =
          dents_.insert_check(dst_name, StrViewComp(), commit_data);
      assert(success);
    }

    std::string new_name(dst_name);

    // Guard against races with readers.
    {
      rt::SpinGuard g(dent->lock_);
      std::swap(new_name, dent->name_);
      dents_.insert_commit(*dent, commit_data);
      dent->parent_.store(getdir().get_entry(), std::memory_order_relaxed);
    }

    return {};
  }

  // Get a pointer a directory entry. This pointer is only valid while the
  // dentry map lock is held.
  [[nodiscard]] Status<DirectoryEntry *> FindRaw(std::string_view key) {
    assert_locked_shared();
    auto it = dents_.find(key, StrViewComp());
    if (it == dents_.end()) return MakeError(ENOENT);
    return &*it;
  }

  // Get a shared pointer to a directory entry.
  Status<std::shared_ptr<DirectoryEntry>> FindShared(std::string_view key) {
    assert_locked_shared();
    auto it = dents_.find(key, StrViewComp());
    if (it == dents_.end()) return MakeError(ENOENT);
    return it->intrusive_ref_;
  }

  // Get a shared pointer to a directory entry.
  Status<std::shared_ptr<Inode>> FindInode(std::string_view key) {
    assert_locked_shared();
    auto it = dents_.find(key, StrViewComp());
    if (it == dents_.end()) return MakeError(ENOENT);
    return it->get_inode();
  }

  bool contains(std::string_view key) {
    assert_locked_shared();
    return dents_.find(key, StrViewComp()) != dents_.end();
  }

  template <typename F>
  void ForEach(F func) {
    assert_locked_shared();
    for (auto &dirent : dents_) func(dirent);
  }

 private:
  IntrusiveSet<DirectoryEntry, &DirectoryEntry::node> dents_;

  IDir &getdir() { return static_cast<IDir &>(*this); }
  const IDir &getdir() const { return static_cast<const T &>(*this); }

  void assert_locked() const { assert(getdir().lock_.IsHeld()); }
  void assert_locked_shared() const {
    assert(getdir().lock_.IsHeldShared() || getdir().lock_.IsHeld());
  }

  struct StrViewComp {
    bool operator()(const std::string_view v, const DirectoryEntry &c) const {
      return v < c.name_;
    }
    bool operator()(const DirectoryEntry &c, std::string_view v) const {
      return c.name_ < v;
    }
  };

  [[nodiscard]] static bool linked_in_set(DirectoryEntry *ent) {
    return ent->intrusive_ref_ != nullptr;
  }
};

enum class IDirType {
  kUnknown = 0,
  kMem = 1,
};

// IDir is an inode type for directories
class IDir : public Inode, protected DentryMap<IDir> {
 public:
  class Token {
    explicit Token() = default;
    friend IDir;
  };

  IDir(Token, mode_t mode, ino_t inum, IDirType type)
      : Inode(kTypeDirectory | mode, inum), type_(type) {}
  IDir(Token, const struct stat &buf, IDirType type)
      : Inode(kTypeDirectory | buf.st_mode, buf.st_ino), type_(type) {}

  ~IDir() override = default;

  // Opens a file that supports getdents() and getdents64().
  Status<std::shared_ptr<File>> Open(
      uint32_t flags, FileMode fmode,
      std::shared_ptr<DirectoryEntry> dent) override {
    assert(dent == dent_);
    return std::make_shared<DirectoryFile>(flags, fmode, std::move(dent));
  }

  Status<std::shared_ptr<DirectoryEntry>> LookupDent(std::string_view name) {
    rt::SharedLock s(lock_);
    Status<std::shared_ptr<DirectoryEntry>> dent = FindShared(name);
    if (dent) return dent;
    rt::UniqueLock u = s.Upgrade();
    return LookupMissLocked(name);
  }

  // Lookup finds a directory entry by name.
  Status<std::shared_ptr<Inode>> Lookup(std::string_view name) {
    rt::ScopedLock g(lock_);
    Status<std::shared_ptr<Inode>> ino = FindInode(name);
    if (ino) return ino;
    Status<std::shared_ptr<DirectoryEntry>> ret = LookupMissLocked(name);
    if (!ret) return MakeError(ret);
    return (*ret)->get_inode();
  }

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
                                               mode_t mode, FileMode fmode) = 0;
  // GetDents returns a vector of the current entries.
  virtual std::vector<dir_entry> GetDents() = 0;

  virtual Status<void> GetStats(struct stat *buf) const override = 0;

  // Gets a shared pointer to this directory.
  [[nodiscard]] std::shared_ptr<IDir> get_this() {
    return std::static_pointer_cast<IDir>(Inode::get_this());
  };

  [[nodiscard]] std::shared_ptr<DirectoryEntry> &get_entry() { return dent_; }
  [[nodiscard]] DirectoryEntry &get_entry_ref() { return *dent_.get(); }

  void SetParent(std::shared_ptr<DirectoryEntry> dent) {
    assert(!dent_ && dent);
    dent_ = std::move(dent);
  }

  Status<void> Unmount(std::string_view name) {
    rt::ScopedLock g(lock_);
    return UnlinkAndDispose(name);
  }

  IDirType get_idir_type() const { return type_; }

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<Inode>(this));
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(cereal::base_class<Inode>(this));
  }

  template <typename F>
  void ForEach(F func) {
    rt::ScopedLock g(lock_);
    DentryMap<IDir>::ForEach(func);
  }

  // Construct a subfolder of this folder of type T.
  template <typename T, typename... Args>
  std::shared_ptr<DirectoryEntry> AddIDirNoCheck(std::string name,
                                                 Args &&...args) {
    rt::ScopedLock g(lock_);
    DirectoryEntry *de =
        AddIDirLockedNoCheck<T>(std::move(name), std::forward<Args>(args)...);
    return de->shared_from_this();
  }

  // Get a constructor token used to create the root IDir.
  static Token GetInitToken() {
    static bool once;
    assert(!once);
    once = true;
    return Token{};
  }

  // Snapshot should traverse this directory to find inodes.
  virtual bool SnapshotRecurse() { return true; }

  // Should only be used during snapshot restore.
  static Token CerealGetToken() { return Token{}; }

 protected:
  rt::SharedMutex lock_;

  inline void assert_locked() { assert(lock_.IsHeld()); }
  inline void assert_locked_shared() {
    assert(lock_.IsHeldShared() || lock_.IsHeld());
  }

  virtual Status<std::shared_ptr<DirectoryEntry>> LookupMissLocked(
      std::string_view name) = 0;

  // All instantiations of IDirs go through this function, which creates a
  // DirectoryEntry for the IDir and links the IDir with its parent (this).
  template <typename T, typename... Args>
  DirectoryEntry *AddIDirLockedNoCheck(std::string name, Args &&...args) {
    assert_locked();
    auto ret = std::make_shared<T>(Token{}, std::forward<Args>(args)...);
    auto sp =
        std::make_shared<DirectoryEntry>(std::move(name), get_entry(), ret);
    ret->SetParent(sp);
    DirectoryEntry *de = sp.get();
    InsertOverwrite(std::move(sp));
    return de;
  }

  template <typename T, typename... Args>
  Status<void> AddIDirLocked(std::string name, Args &&...args) {
    assert_locked();
    auto ret = std::make_shared<T>(Token{}, std::forward<Args>(args)...);
    auto sp =
        std::make_shared<DirectoryEntry>(std::move(name), get_entry(), ret);
    ret->SetParent(sp);
    return Insert(std::move(sp));
  }

  // Create a directory entry for a non-folder inode in this IDir. The caller
  // must have already checked to ensure that the name is not already in use.
  DirectoryEntry *AddDentLockedNoCheck(std::string name,
                                       std::shared_ptr<Inode> ino) {
    assert_locked();
    assert(!ino->is_dir());
    assert(!contains(name));
    auto sp = std::make_shared<DirectoryEntry>(std::move(name), get_entry(),
                                               std::move(ino));
    DirectoryEntry *de = sp.get();
    InsertOverwrite(std::move(sp));
    return de;
  }

  // Create a directory entry for a non-folder inode in this IDir.
  [[nodiscard]] Status<void> AddDentLocked(std::string name,
                                           std::shared_ptr<Inode> ino) {
    assert_locked();
    assert(!ino->is_dir());
    auto sp = std::make_shared<DirectoryEntry>(std::move(name), get_entry(),
                                               std::move(ino));
    return Insert(std::move(sp));
  }

 private:
  friend class DentryMap<IDir>;
  friend class DirectoryEntry;
  const IDirType type_;

  // This folder's directory entry in its parent.
  std::shared_ptr<DirectoryEntry> dent_;
};

template <typename T>
inline void DentryMap<T>::UnlinkAndDispose(DirectoryEntry *sp) {
  assert_locked();
  sp->Invalidate();
  if (sp->get_inode_ref().is_dir()) {
    // If it points to an IDir, delete its pointer.
    IDir &dir = static_cast<IDir &>(sp->get_inode_ref());
    dir.dent_.reset();
  }
  assert(linked_in_set(sp));
  dents_.erase(decltype(dents_)::s_iterator_to(*sp));
  sp->intrusive_ref_.reset();
}

// FSRoot manages the root directory and namespace for a process
class FSRoot {
 public:
  FSRoot(std::shared_ptr<DirectoryEntry> root,
         std::shared_ptr<DirectoryEntry> cwd)
      : root_(std::move(root)), cwd_(std::move(cwd)) {}
  FSRoot(std::shared_ptr<IDir> root, std::shared_ptr<IDir> cwd)
      : root_(root->get_entry()), cwd_(cwd->get_entry()) {}

  ~FSRoot() = default;

  FSRoot(const FSRoot &other)
      : root_(other.root_), cwd_(other.get_cwd_ent()), umask_(other.umask_) {}

  [[nodiscard]] std::shared_ptr<IDir> get_root() const {
    return std::static_pointer_cast<IDir>(root_->get_inode());
  }
  [[nodiscard]] std::shared_ptr<IDir> get_cwd() const {
    return std::static_pointer_cast<IDir>(
        cwd_.load(std::memory_order_acquire)->get_inode());
  }

  [[nodiscard]] std::shared_ptr<DirectoryEntry> get_root_ent() const {
    return root_;
  }
  [[nodiscard]] std::shared_ptr<DirectoryEntry> get_cwd_ent() const {
    return cwd_.load(std::memory_order_acquire);
  }

  [[nodiscard]] static FSRoot &GetGlobalRoot() { return *global_root_; }
  [[nodiscard]] mode_t get_umask() const { return umask_; }

  // Caller must synchronize this call with a lock.
  void SetCwd(std::shared_ptr<DirectoryEntry> new_cwd) {
    cwd_ = std::move(new_cwd);
  }

  // Caller must synchronize this call with a lock.
  void SetCwd(std::shared_ptr<IDir> new_cwd) { cwd_ = new_cwd->get_entry(); }

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
  std::shared_ptr<DirectoryEntry> root_;
  std::atomic<std::shared_ptr<DirectoryEntry>> cwd_;
  mode_t umask_{0};
  static FSRoot *global_root_;
};

// Get the parent directory entry.
[[nodiscard]] inline IDir &DirectoryEntry::get_parent_dir_locked() const {
  return static_cast<IDir &>(get_parent_ent_locked().get_inode_ref());
}

namespace linuxfs {
Status<void> MountLinux(IDir &parent, std::string name, std::string_view path);
Status<std::shared_ptr<IDir>> InitLinuxRoot();
}  // namespace linuxfs

namespace memfs {
std::shared_ptr<IDir> MkFolder(IDir &parent, std::string name,
                               mode_t mode = S_IRWXU);
Status<void> InitMemfs();
void MemFSStartTracer(IDir &root);
void MemFSEndTracer();
}  // namespace memfs

Status<void> FSSnapshot(cereal::BinaryOutputArchive &ar);
Status<void> FSRestore(cereal::BinaryInputArchive &ar);

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

Status<std::shared_ptr<DirectoryEntry>> LookupDirEntry(const FSRoot &fs,
                                                       std::string_view path,
                                                       bool chase_link = true);
}  // namespace junction
