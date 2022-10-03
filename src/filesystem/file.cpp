#include "filesystem/file.hpp"

#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <mutex>
#include <string>

namespace junction {

constexpr int PROT = PROT_EXEC | PROT_READ;
constexpr int FLAGS = MAP_PRIVATE;

File::File(int fd, const std::string file_path, bool _is_dir)
    : _fd(fd), _file_path(file_path), _is_dir(_is_dir) {
  // Obtain stats for the file and cache them since we will not be allowing
  // this operation via syscalls later. Given that this will be a read-only
  // file, the stats should not change and it is safe to cache them once.
  if (::fstat(_fd, &_stat)) [[unlikely]] {
    std::cerr << "Cannot create file; unable to fstat: " << fd << std::endl;
    throw std::runtime_error("Cannot create file");
  }

  if (!_is_dir) {
    _mmap_length = _stat.st_size;
  }

  if (_map_no_lock()) [[unlikely]] {
    std::cerr << "Cannot create file; unable to _map:" << _fd << std::endl;
    throw std::runtime_error("Cannot create file");
  }
}

File::~File() {
  // Unmap any memory that was mapped for this file.
  if (_unmap_no_lock()) [[unlikely]] {
    std::cerr << "Cannot destroy file; failed to _unmap: " << _fd
              << std::endl;
  }

  // Close the kernel-provided file descriptor. Here, we assume the syscalls
  // are allowed.
  if (::close(_fd)) [[unlikely]] {
    std::cerr << "Cannot destroy file; failed to close: " << _fd << std::endl;
  }
}

int File::openat() {
  std::lock_guard<decltype(_mutex)> lock(_mutex);

  if (_map_no_lock()) [[unlikely]] {
    std::cerr << "Canont openat file; failed to _map: " << _fd << std::endl;
    return 1;
  }

  return 0;
}

int File::fstat(struct stat* buf) {
  std::lock_guard<decltype(_mutex)> lock(_mutex);

  if (!buf) [[unlikely]] {
    std::cerr << "Cannot fstat; output buffer not provided" << std::endl;
    return -1;
  }

  memcpy(buf, &_stat, sizeof(struct stat));

  return 0;
}

// TODO(gohar): This is a very weak implementation. We need to check if there a
// directory that we had opened earlier, then all paths relative to that should
// be correctly handled.
int File::fstatat(int dirfd, struct stat* buf, int flags) {
  std::lock_guard<decltype(_mutex)> lock(_mutex);

  if (!buf) [[unlikely]] {
    std::cerr << "Cannot fstatat64; output buffer not provided" << std::endl;
    return -1;
  }

  if (dirfd != AT_FDCWD) [[unlikely]] {
    std::cerr << "Unsupported dirfd: " << dirfd << " (!= " << AT_FDCWD << ")"
              << std::endl;
    return -1;
  }

  // TODO(gohar): Handle flags appropriately.
  memcpy(buf, &_stat, sizeof(struct stat));

  return 0;
}

off_t File::lseek(off_t offset, int whence) {
  if (_is_dir) {
    std::cerr << "Cannot lseek; directory: " << _file_path << std::endl;
    return -1;
  }

  std::lock_guard<decltype(_mutex)> lock(_mutex);

  if (whence != SEEK_CUR) [[unlikely]] {
    std::cerr << "Cannot lseek; unsupported whence: " << whence << std::endl;
    return -1;
  }

  const size_t new_offset = _offset + offset;

  if (new_offset >= _stat.st_size) [[unlikely]] {
    std::cerr << "Cannot seek past the file size: (" << new_offset << " > "
              << _stat.st_size << ")" << std::endl;
    return -1;
  }

  _offset = new_offset;

  return _offset;
}

ssize_t File::read(void* buf, size_t count) {
  if (_is_dir) {
    std::cerr << "Cannot read; directory: " << _file_path << std::endl;
    return -1;
  }

  std::lock_guard<decltype(_mutex)> lock(_mutex);

  if (count == 0) [[unlikely]] {
    return 0;
  }

  if (!buf) [[unlikely]] {
    std::cerr << "Cannot read; output buffer not provided" << std::endl;
    return -1;
  }

  // If the file has not been memory mapped yet, map it.
  if (!_mmap && _map_no_lock()) [[unlikely]] {
    std::cerr << "Cannot read; file not mapped: " << _fd << std::endl;
    return -1;
  }

  const size_t max_readable_bytes = _stat.st_size - _offset;
  if (max_readable_bytes == 0) {
    // No more data to read, the offset is already at the end.
    return 0;
  }

  // Clip the maximum possible bytes that can be read.
  if (count > max_readable_bytes) {
    count = max_readable_bytes;
  }

  // Calculate where to start reading from and copy from that location onwards.
  const void* src = static_cast<const char*>(_mmap) + _offset;
  memcpy(buf, src, count);

  // Update the offset for this file.
  _offset += count;

  return count;
}

ssize_t File::write(const void* buf, size_t count) { return -1; }

int File::close() {
  std::lock_guard<decltype(_mutex)> lock(_mutex);

  // Unmap the file but don't close the kernel-provided file descriptor as it
  // may be "opened" again.
  if (_unmap_no_lock()) {
    return -1;
  }

  return 0;
}

int File::_map_no_lock() {
  if (_is_dir) {
    return 0;
  }

  // if (_mmap) [[unlikely]] {
  //   std::cerr << "Cannot _map; file already mapped: " << _fd << std::endl;
  //   return 0;
  // }

  // Always map from the beginning.
  _mmap = mmap(nullptr /* addr */, _mmap_length, PROT, FLAGS, _fd, 0);
  if (_mmap == MAP_FAILED) [[unlikely]] {
    std::cerr << "Cannot create file; unable to mmap: " << _fd << ", "
              << _file_path << std::endl;
    perror("mmap");
    return -1;
  }

  return 0;
}

int File::_unmap_no_lock() {
  if (_is_dir) {
    return 0;
  }

  if (!_mmap) [[unlikely]] {
    std::cerr << "Cannot _unmap; file not mapped: " << _fd << std::endl;
    return 0;
  }

  _offset = 0;
  _mmap = nullptr;

  return munmap(_mmap, _mmap_length);
}

}  // namespace junction