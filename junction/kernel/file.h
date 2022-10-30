// file.h - support for the UNIX file abstraction

#pragma once

extern "C" {
#include <fcntl.h>
}

#include <memory>
#include <span>

#include "junction/base/error.h"
#include "junction/bindings/rcu.h"
#include "junction/bindings/sync.h"

namespace junction {

//
// File flags (set by open() and fcntl()).
//

// File is opened in append mode.
constexpr unsigned int kFlagAppend = O_APPEND;
// File should be truncated to zero.
constexpr unsigned int kFlagTruncate = O_TRUNC;
// File was created if it didn't exist.
constexpr unsigned int kFlagCreate = O_CREAT;
// File must be a directory.
constexpr unsigned int kFlagDirectory = O_DIRECTORY;
// File is using nonblocking I/O.
constexpr unsigned int kFlagNonblock = O_NONBLOCK;
// Write operations will flush to disk.
constexpr unsigned int kFlagSync = O_SYNC;

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
  virtual ~File() = default;
  virtual Status<size_t> Read(std::span<std::byte> buf, off_t *off) {
    return MakeError(EINVAL);
  }
  virtual Status<size_t> Write(std::span<const std::byte> buf, off_t *off) {
    return MakeError(EINVAL);
  }
  virtual Status<off_t> Seek(off_t off, SeekFrom origin) {
    return MakeError(EINVAL);
  }
  virtual Status<void> Sync() { return {}; }

  [[nodiscard]] unsigned int get_flags() const { return flags_; }

 private:
  off_t off_;
  unsigned int flags_;
  unsigned int mode_;
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
  ~FileTable();

  // Returns a raw pointer to a file for a given fd number. Returns nullptr if
  // the file does not exist. This fast path does not refcount the file.
  File *Get(int fd);

  // Returns a shared pointer to a file for a given fd number. Typically this
  // is used for dup() or clone() system calls. If the file does not exist,
  // the shared pointer will be empty.
  std::shared_ptr<File> Dup(int fd);

  // Inserts a file into the file table and refcounts it. Returns the fd number.
  int Insert(std::shared_ptr<File> f);

  // Inserts a file into the file table at a specific fd number and refcounts
  // it. If a file already exists for the fd number, it will be replaced
  // atomically.
  void InsertAt(int fd, std::shared_ptr<File> f);

  // Removes the file tied to an fd number and drops its refcount.
  void Remove(int fd);

 private:
  using FArr = detail::file_array;

  // Adjust the file descriptor table's size if needed.
  void Resize(size_t len);

  std::unique_ptr<FArr> farr_;
  rt::RCUPtr<FArr> rcup_;
  rt::Spin lock_;
};

inline File *FileTable::Get(int fd) {
  rt::RCURead l;
  rt::RCUReadGuard g(&l);
  const FArr *tbl = rcup_.get();
  if (unlikely(static_cast<size_t>(fd) >= tbl->len)) return nullptr;
  return tbl->files[fd].get();
}

}  // namespace junction
