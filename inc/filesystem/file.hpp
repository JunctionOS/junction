#pragma once

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <utility>

#include "base/lock.hpp"

namespace junction {

/* Internal file representation/state for an open file descriptor. */
class File {
public:
  File() {}
  File(int fd, const std::string file_path, bool is_dir);
  ~File();

  /* explicit move definition */
  File(File&& other) { _move_helper(std::move(other)); }
  File& operator=(File&& other) {
    _move_helper(std::move(other));
    return *this;
  }

  /* disallow copy */
  File(const File& temp_obj) = delete;
  File& operator=(const File& temp_obj) = delete;

  int openat();
  int fstat(struct stat* buf);
  off_t lseek(off_t offset, int whence);
  ssize_t read(void* buf, size_t count);
  ssize_t write(const void* buf, size_t count);
  int close();

  const void* memory(const size_t file_offset) const;
  size_t size() const;

private:
  /* WARNING: Must update move_helper if any variables are added. */

  // Kernel file descriptor associated with this file.
  int _fd{-1};

  // Path pointed to by this file.
  std::string _file_path;

  // Is this a directory?
  bool _is_dir;

  // stat structure associated with this file (obtained from the kernel).
  struct stat _stat;

  // Protects against changes to offset / position cache from multiple threads.
  Lock _mutex;

  // Requested/current position
  size_t _offset{0};

  // Pointer to mmap region of this file in memory; if the corresponding file
  // descriptor is closed, we will munmap this and mmap again later when opened.
  // The file decriptor itself will not be closed.
  void* _mmap{nullptr};

  void _move_helper(File&& other) {
    std::swap(_fd, other._fd);
    std::swap(_file_path, other._file_path);
    std::swap(_is_dir, other._is_dir);
    std::swap(_stat, other._stat);
    std::swap(_offset, other._offset);
    std::swap(_mmap, other._mmap);
  }

  int _mmap_no_lock();
  int _munmap_no_lock();
};

} // namespace junction