// file.h - support for the UNIX file abstraction

#pragma once

extern "C" {
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
}

#include <memory>
#include <span>

#include "junction/base/bitmap.h"
#include "junction/base/error.h"
#include "junction/bindings/rcu.h"
#include "junction/bindings/sync.h"
#include "junction/fs/poll.h"
#include "junction/fs/procfs/procfs.h"
#include "junction/snapshot/cereal.h"

namespace junction {

//
// Types of files.
//

enum class FileType : int {
  kNormal = 0,
  kDirectory,
  kSocket,
  kSpecial,
  kSymlink,
};

//
// File flags (set by open() and fcntl()).
//

// File is opened in append mode.
inline constexpr unsigned int kFlagAppend = O_APPEND;
// File should be truncated to zero.
inline constexpr unsigned int kFlagTruncate = O_TRUNC;
// File was created if it didn't exist.
inline constexpr unsigned int kFlagCreate = O_CREAT;
// Create an unnamed temporary regular file.
inline constexpr unsigned int kFlagTemp = O_TMPFILE;
// File must be a directory.
inline constexpr unsigned int kFlagDirectory = O_DIRECTORY;
// File is using nonblocking I/O.
inline constexpr unsigned int kFlagNonblock = O_NONBLOCK;
// Write operations will flush to disk.
inline constexpr unsigned int kFlagSync = O_SYNC;
// Close this FD on exec().
inline constexpr unsigned int kFlagCloseExec = O_CLOEXEC;
// File must not already exist.
inline constexpr unsigned int kFlagExclusive = O_EXCL;
// Basename cannot point to a symlink.
inline constexpr unsigned int kFlagNoFollow = O_NOFOLLOW;
// File descriptor is purely a reference to this path.
inline constexpr unsigned int kFlagPath = O_PATH;

//
// AT flags used with *at system calls (openat, newfstatat, etc).
//

// Resolve symlink at the end of the path.
inline constexpr unsigned int kAtFollowLink = AT_SYMLINK_FOLLOW;
// Do not resolve symlink at the end of the path.
inline constexpr unsigned int kAtNoFollowLink = AT_SYMLINK_NOFOLLOW;
// Special file descriptor value referring to the cwd.
inline constexpr int kAtFdCwd = AT_FDCWD;
// Remove a directory.
inline constexpr unsigned int kAtRemoveDir = AT_REMOVEDIR;
// An empty path means the dirfd is operated on directly.
inline constexpr unsigned int kAtEmptyPath = AT_EMPTY_PATH;

//
// File permission modes.
//

enum class FileMode : unsigned int {
  kRead = O_RDONLY,
  kWrite = O_WRONLY,
  kReadWrite = O_RDWR,
};

inline constexpr unsigned int kAccessModeMask = O_ACCMODE;

inline constexpr std::pair<unsigned int, FileMode> FromFlags(
    unsigned int flags) {
  return {flags & ~kAccessModeMask,
          static_cast<FileMode>(flags & kAccessModeMask)};
}

inline constexpr unsigned int ToFlags(FileMode mode) {
  return static_cast<unsigned int>(mode);
}

//
// Seek from operations.
//

enum class SeekFrom : int {
  kStart = SEEK_SET,
  kEnd = SEEK_END,
  kCurrent = SEEK_CUR,
};

// Forward declaration
class Inode;
class IDir;
class ISoftLink;
class DirectoryEntry;

// The base class for UNIX files.
class File : public std::enable_shared_from_this<File> {
 public:
  File(FileType type, unsigned int flags, FileMode mode,
       std::shared_ptr<DirectoryEntry> ent);
  File(FileType type, unsigned int flags, FileMode mode)
      : type_(type), flags_(flags), mode_(mode), ino_(nullptr) {}

  virtual ~File() = default;

  virtual Status<size_t> Read(std::span<std::byte> buf, off_t *off) {
    return MakeError(EINVAL);
  }
  virtual Status<size_t> Write(std::span<const std::byte> buf, off_t *off) {
    return MakeError(EINVAL);
  }

  Status<void> Truncate(off_t newlen);

  virtual Status<off_t> Seek(off_t off, SeekFrom origin) {
    return MakeError(ESPIPE);
  }
  virtual Status<void> Sync() { return {}; }
  virtual Status<void *> MMap(void *addr, size_t length, int prot, int flags,
                              off_t off) {
    return MakeError(EINVAL);
  }

  virtual Status<long> GetDents(std::span<std::byte> dirp, off_t *off) {
    return MakeError(ENOTDIR);
  }

  virtual Status<long> GetDents64(std::span<std::byte> dirp, off_t *off) {
    return MakeError(ENOTDIR);
  }

  virtual Status<long> ReadLink(std::span<std::byte> buf) {
    return MakeError(EINVAL);
  }

  virtual Status<void> Stat(struct stat *statbuf) const;
  virtual Status<void> StatFS(struct statfs *buf) const;

  virtual Status<void> Ioctl(unsigned long request, char *argp);

  // Default readv/writev implementations that falls back to write internally
  virtual Status<size_t> Writev(std::span<const iovec> vec, off_t *off);
  virtual Status<size_t> Readv(std::span<iovec> vec, off_t *off);

  // getters and setters
  [[nodiscard]] FileType get_type() const { return type_; }
  [[nodiscard]] unsigned int get_flags() const { return flags_; }
  void set_flags(unsigned int flags) {
    NotifyFlagsChanging(flags_, flags);
    flags_ = flags;
  }
  void set_flag(unsigned int flag) {
    NotifyFlagsChanging(flags_, flags_ | flag);
    flags_ |= flag;
  }
  void clear_flag(unsigned int flag) {
    NotifyFlagsChanging(flags_, flags_ & ~flag);
    flags_ &= ~flag;
  }
  [[nodiscard]] FileMode get_mode() const { return mode_; }
  [[nodiscard]] bool is_readable() const { return mode_ != FileMode::kWrite; }
  [[nodiscard]] bool is_writeable() const { return mode_ != FileMode::kRead; }
  [[nodiscard]] off_t &get_off_ref() { return off_; }
  [[nodiscard]] bool is_nonblocking() const {
    return get_flags() & kFlagNonblock;
  }
  [[nodiscard]] Inode *get_inode() const { return ino_; }
  [[nodiscard]] const Inode &get_inode_ref() const { return *ino_; }
  [[nodiscard]] Inode &get_inode_ref() { return *ino_; }
  [[nodiscard]] PollSource &get_poll_source() {
    if (unlikely(!IsPollSourceSetup())) {
      poll_source_setup_ = true;
      SetupPollSource();
    }
    return poll_;
  }

  [[nodiscard]] std::shared_ptr<DirectoryEntry> get_dent() const {
    return dent_;
  }

  [[nodiscard]] DirectoryEntry &get_dent_ref() const { return *dent_.get(); }

  [[nodiscard]] virtual std::string get_filename() const;

  // There is some limitation in cereal's polymorphic type registration that
  // seems to require base/derived classes to both use save/load or serialize.
  // Use save/load here so that derived classes have more flexibility.
  template <class Archive>
  void save(Archive &ar) const {
    ar(flags_, off_, poll_);
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(flags_, off_, poll_);
  }

  // Add so that Cereal doesn't require this class to be default constructible.
  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<File> &construct) {
    std::unreachable();
  }

  [[nodiscard]] virtual size_t get_size() const { return 0; }

  [[nodiscard]] procfs::ProcFSData &get_procfs() { return procfs_data_; }

  // Returns true if this file can be deduplicated in a snapshot, ie it is
  // visible in the Linux host filesystem. Overriden by subclasses that expose
  // Linux files.
  [[nodiscard]] virtual bool SnapshotShareable() const { return false; }

 protected:
  [[nodiscard]] bool IsPollSourceSetup() const { return poll_source_setup_; }

  // File implementations can override this method to subscribe to flag changes
  virtual void NotifyFlagsChanging(unsigned int oldflags,
                                   unsigned int newflags) {}

 private:
  virtual void SetupPollSource() {}

  const FileType type_;
  unsigned int flags_;
  const FileMode mode_;
  off_t off_{0};
  bool poll_source_setup_{false};
  PollSource poll_;
  Inode *const ino_;
  const std::shared_ptr<DirectoryEntry> dent_;
  procfs::ProcFSData procfs_data_;
};

class SeekableFile : public File {
 public:
  using File::File;
  Status<off_t> Seek(off_t off, SeekFrom origin) final override {
    switch (origin) {
      case SeekFrom::kStart:
        return off;
      case SeekFrom::kCurrent:
        return get_off_ref() + off;
      case SeekFrom::kEnd:
        return get_size() + off;
      default:
        return MakeError(EINVAL);
    }
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(cereal::base_class<File>(this));
  }

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<File>(this));
  }
};

// Class for a directory file, supports getdents and getdents64.
class DirectoryFile : public File {
 public:
  DirectoryFile(unsigned int flags, FileMode mode,
                std::shared_ptr<DirectoryEntry> dent);
  Status<long> GetDents(std::span<std::byte> dirp, off_t *off) override;
  Status<long> GetDents64(std::span<std::byte> dirp, off_t *off) override;
};

// Class for a symlink file, supports readlink.
class SoftLinkFile : public File {
 public:
  SoftLinkFile(unsigned int flags, FileMode mode,
               std::shared_ptr<DirectoryEntry> dent);
  Status<long> ReadLink(std::span<std::byte> buf) override;
};

namespace detail {

struct file_array : public rt::RCUObject {
  explicit file_array(size_t cap);
  ~file_array();

  // Constructor for cereal
  file_array(size_t len, size_t cap,
             std::unique_ptr<std::shared_ptr<File>[]> &&files)
      : len(len), cap(cap), files(std::move(files)) {}

  template <class Archive>
  void save(Archive &ar) const {
    ar(len, cap);
    for (size_t i = 0; i < len; i++) ar(files[i]);
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<file_array> &construct) {
    size_t len, cap;
    ar(len, cap);
    if (unlikely(cap >= ArrayMaxElements<std::shared_ptr<File>>()))
      throw std::bad_alloc();
    std::unique_ptr<std::shared_ptr<File>[]> arr =
        std::make_unique<std::shared_ptr<File>[]>(cap);
    for (size_t i = 0; i < len; i++) ar(arr[i]);
    construct(len, cap, std::move(arr));
  }

  size_t len = 0, cap;
  std::unique_ptr<std::shared_ptr<File>[]> files;
};

std::unique_ptr<file_array> CopyFileArray(const file_array &src, size_t cap);

}  // namespace detail

class FileTable {
 public:
  FileTable();
  ~FileTable();

  // Copy and move support.
  FileTable(const FileTable &o);
  FileTable &operator=(const FileTable &o);
  FileTable(FileTable &&o)
      : farr_(std::move(o.farr_)),
        rcup_(farr_.get()),
        close_on_exec_(std::move(o.close_on_exec_)) {}
  FileTable &operator=(FileTable &&o) {
    farr_ = std::move(o.farr_);
    rcup_.set(farr_.get());
    close_on_exec_ = std::move(o.close_on_exec_);
    return *this;
  }

  // Returns a raw pointer to a file for a given fd number. Returns nullptr
  // if the file does not exist. This fast path does not refcount the file.
  File *Get(int fd);

  // Returns a shared pointer to a file for a given fd number. Typically this
  // is used for dup() or clone() system calls. If the file does not exist,
  // the shared pointer will be empty.
  std::shared_ptr<File> Dup(int fd);

  // Inserts a file into the file table and refcounts it. Returns the fd number.
  int Insert(std::shared_ptr<File> f, bool cloexec = false, size_t lowest = 0);

  // Inserts a file into the file table at a specific fd number and refcounts
  // it. If a file already exists for the fd number, it will be replaced
  // atomically.
  void InsertAt(int fd, std::shared_ptr<File> f, bool cloexec = false);

  // Removes the file tied to an fd number and drops its refcount. Returns true
  // if successful.
  bool Remove(int fd);

  // Removes fds in the range low to high (inclusive).
  void RemoveRange(int low, int high);

  // Destroy a file table by dropping its file array. Called only when the
  // FileTable is no longer in use and will never be used again.
  void Destroy() { farr_.reset(); }

  // Sets an fd as close-on-exec.
  void SetCloseOnExec(int fd);

  // Set close-on-exec for fds in range low to high (inclusive).
  void SetCloseOnExecRange(int low, int high);

  // Tests if an fd is close-on-exec.
  bool TestCloseOnExec(int fd);

  // Set an fd as not close-on-exec.
  void ClearCloseOnExec(int fd);

  // Runs a function on each file descriptor in the table. Preemption is
  // disabled during each call to the function.
  template <typename F>
  void ForEach(F func);

  // Close all files marked close-on-exec.
  void DoCloseOnExec();

  template <class Archive>
  void save(Archive &ar) const {
    ar(farr_, close_on_exec_);
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(farr_, close_on_exec_);
    rcup_.set(farr_.get());
  }

 private:
  using FArr = detail::file_array;

  // Adjust the file descriptor table's size if needed.
  void Resize(size_t len);

  std::unique_ptr<FArr> farr_;
  rt::RCUPtr<FArr> rcup_;
  dynamic_bitmap close_on_exec_;
  rt::Spin lock_;
};

inline File *FileTable::Get(int fd) {
  rt::RCURead l;
  rt::RCUReadGuard g(l);
  const FArr *tbl = rcup_.get();
  if (unlikely(static_cast<size_t>(fd) >= tbl->len)) return nullptr;
  return tbl->files[fd].get();
}

template <typename F>
void FileTable::ForEach(F func) {
  rt::RCURead l;
  int fd = 0;
  while (true) {
    rt::RCUReadGuard g(l);
    const FArr *tbl = rcup_.get();
    if (unlikely(static_cast<size_t>(fd) >= tbl->len)) break;
    File *f = tbl->files[fd++].get();
    if (!f) continue;
    func(*f, fd - 1);
  }
}

}  // namespace junction
