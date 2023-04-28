// file.h - support for the UNIX file abstraction

#pragma once

extern "C" {
#include <fcntl.h>
#include <sys/stat.h>
}

#include <memory>
#include <span>

#include "junction/base/bitmap.h"
#include "junction/base/error.h"
#include "junction/bindings/rcu.h"
#include "junction/bindings/sync.h"
#include "junction/kernel/poll.h"

namespace junction {

//
// Types of files.
//

enum class FileType : int {
  kNormal = 0,
  kDirectory,
  kSocket,
  kSpecial,
};

//
// File flags (set by open() and fcntl()).
//

// File is opened in append mode.
constexpr unsigned int kFlagAppend = O_APPEND;
// File should be truncated to zero.
constexpr unsigned int kFlagTruncate = O_TRUNC;
// File was created if it didn't exist.
constexpr unsigned int kFlagCreate = O_CREAT;
// Create an unnamed temporary regular file.
constexpr unsigned int kFlagTemp = O_TMPFILE;
// File must be a directory.
constexpr unsigned int kFlagDirectory = O_DIRECTORY;
// File is using nonblocking I/O.
constexpr unsigned int kFlagNonblock = O_NONBLOCK;
// Write operations will flush to disk.
constexpr unsigned int kFlagSync = O_SYNC;
// Close this FD on exec().
constexpr unsigned int kFlagCloseExec = O_CLOEXEC;

//
// File permission modes.
//

constexpr unsigned int kModeRead = O_RDONLY;
constexpr unsigned int kModeWrite = O_WRONLY;
constexpr unsigned int kModeReadWrite = O_RDWR;

//
// Seek from operations.
//

enum class SeekFrom : int {
  kStart = SEEK_SET,
  kEnd = SEEK_END,
  kCurrent = SEEK_CUR,
};

// The base class for UNIX files.
class File {
 public:
  File(FileType type, unsigned int flags, unsigned int mode)
      : type_(type), flags_(flags), mode_(mode) {}
  virtual ~File() = default;

  virtual Status<size_t> Read(std::span<std::byte> buf, off_t *off) {
    return MakeError(EINVAL);
  }
  virtual Status<size_t> Write(std::span<const std::byte> buf, off_t *off) {
    return MakeError(EINVAL);
  }
  virtual Status<void> Truncate(off_t newlen) { return MakeError(EINVAL); }
  virtual Status<void> Allocate(int mode, off_t offset, off_t len) {
    return MakeError(EINVAL);
  }
  virtual Status<off_t> Seek(off_t off, SeekFrom origin) {
    return MakeError(EINVAL);
  }
  virtual Status<void> Sync() { return MakeError(EINVAL); }
  virtual Status<void *> MMap(void *addr, size_t length, int prot, int flags,
                              off_t off) {
    return MakeError(EINVAL);
  }
  virtual Status<void> Stat(struct stat *statbuf, int flags) {
    return MakeError(EINVAL);
  }
  virtual Status<int> GetDents(void *dirp, unsigned int count) {
    return MakeError(EINVAL);
  }
  virtual Status<int> GetDents64(void *dirp, unsigned int count) {
    return MakeError(EINVAL);
  }
  virtual Status<void> Ioctl(unsigned long request, char *argp) {
    return MakeError(EINVAL);
  }

  // Default writev implementation that falls back to write internally
  virtual Status<size_t> Writev(std::span<const iovec> vec, off_t *off);

  [[nodiscard]] FileType get_type() const { return type_; }
  [[nodiscard]] unsigned int get_flags() const { return flags_; }
  [[nodiscard]] unsigned int get_mode() const { return mode_; }
  [[nodiscard]] off_t &get_off_ref() { return off_; }
  [[nodiscard]] bool is_nonblocking() const {
    return get_flags() & kFlagNonblock;
  }

  void set_flags(unsigned int flags) {
    NotifyFlagsChanging(flags_, flags);
    flags_ = flags;
  }
  [[nodiscard]] PollSource &get_poll_source() {
    if (unlikely(!IsPollSourceSetup())) {
      poll_source_setup_ = true;
      SetupPollSource();
    }
    return poll_;
  }

 protected:
  [[nodiscard]] bool IsPollSourceSetup() const { return poll_source_setup_; }

  // File implementations can override this method to subscribe to flag changes
  virtual void NotifyFlagsChanging(unsigned int oldflags,
                                   unsigned int newflags) {}

 private:
  virtual void SetupPollSource() {}

  const FileType type_;
  unsigned int flags_;
  const unsigned int mode_;
  off_t off_{0};
  bool poll_source_setup_{false};
  PollSource poll_;
};

namespace detail {

struct file_array {
  explicit file_array(size_t cap);
  ~file_array();

  size_t len = 0, cap;
  std::unique_ptr<std::shared_ptr<File>[]> files;
};

std::unique_ptr<file_array> CopyFileArray(const file_array &src, size_t cap);

}  // namespace detail

class FileTable {
 public:
  FileTable();
  FileTable(const FileTable &o);
  ~FileTable();

  // Returns a raw pointer to a file for a given fd number. Returns nullptr if
  // the file does not exist. This fast path does not refcount the file.
  File *Get(int fd);

  // Returns a shared pointer to a file for a given fd number. Typically this
  // is used for dup() or clone() system calls. If the file does not exist,
  // the shared pointer will be empty.
  std::shared_ptr<File> Dup(int fd);

  // Inserts a file into the file table and refcounts it. Returns the fd number.
  int Insert(std::shared_ptr<File> f, size_t lowest = 0, bool cloexec = false);

  // Inserts a file into the file table at a specific fd number and refcounts
  // it. If a file already exists for the fd number, it will be replaced
  // atomically.
  void InsertAt(int fd, std::shared_ptr<File> f, bool cloexec = false);

  // Removes the file tied to an fd number and drops its refcount. Returns true
  // if successful.
  bool Remove(int fd);

  // Sets an fd as close-on-exec.
  void SetCloseOnExec(int fd);

  // Tests if an fd is close-on-exec.
  bool TestCloseOnExec(int fd);

  // Runs a function on each file descriptor in the table. Preemption is
  // disabled during each call to the function.
  template <typename F>
  void ForEach(F func);

  // Close all files marked close-on-exec.
  void DoCloseOnExec();

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
    func(*f);
  }
}

}  // namespace junction
