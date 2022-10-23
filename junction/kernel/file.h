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
  virtual Status<size_t> Read(std::span<std::byte> buf) {
    return MakeError(EINVAL);
  }
  virtual Status<size_t> Write(std::span<const std::byte> buf) {
    return MakeError(EINVAL);
  }
  virtual Status<off_t> Seek(off_t off, SeekFrom origin) {
    return MakeError(EINVAL);
  }
  virtual Status<void> Sync() { return {}; }

  off_t get_offset() const { return off_; }
  unsigned int get_flags() const { return flags_; }

 private:
  off_t off_;
  unsigned int flags_;
  unsigned int mode_;
};

namespace detail {

struct file_array {
  std::size_t len_;
  std::shared_ptr<File> *files_;
};

}  // namespace detail

class FileTable {
 public:
  File *Get(int fd);
  int Insert(std::shared_ptr<File> f);
  void Remove(int fd);

 private:
  using FArr = detail::file_array;

  std::unique_ptr<FArr> farr_;
  rt::RCUPtr<FArr> rcup_;
  rt::Spin lock_;
};

File *FileTable::Get(int fd) {}

}  // namespace junction
