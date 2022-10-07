#include "filesystem/file.hpp"

#include "spdlog/spdlog.h"
#include <fcntl.h>
#include <string.h>
#include <cstring>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <assert.h>

#include <iostream>
#include <mutex>
#include <string>

namespace junction {

constexpr int PROT = PROT_EXEC | PROT_READ;
constexpr int FLAGS = MAP_PRIVATE;

/* Creates a File object. The fd provided should be a valid, pre-opened fd. */
File::File(int fd, const std::string file_path, bool _is_dir)
    : _fd(fd), _file_path(file_path), _is_dir(_is_dir) {
  // Obtain stats for the file and cache them since we will not be allowing
  // this operation via syscalls later. Given that this will be a read-only
  // file, the stats should not change and it is safe to cache them once.
  auto res = syscall_no_intercept(SYS_fstat, _fd, &_stat);
  {
    const int err = syscall_error_code(res);
    if (err != 0) {
      spdlog::error("Cannot create file: {0}", strerror(err));
      throw std::runtime_error("Cannot create file");
    }
  }

  // Map the file.
  if (!_is_dir) {
    if (_mmap_no_lock()) [[unlikely]] {
      std::cerr << "Cannot create file; unable to _map:" << _fd << std::endl;
      throw std::runtime_error("Cannot create file");
    }
  }
}

File::~File() {
  // Unmap all the memory that was mapped for this file.
  if (_munmap_no_lock()) [[unlikely]] {
    std::cerr << "Cannot destroy file; failed to _munmap: " << _fd << std::endl;
  }

  // Close the kernel-provided file descriptor.
  // Here, we assume syscalls are allowed.
  auto res = syscall_no_intercept(SYS_close, _fd);
  {
    const int err = syscall_error_code(res);
    if (err != 0) {
      spdlog::error("Cannot close: {0}", strerror(err));
    }
  }
}

const void* File::memory(const size_t file_offset) const {
  assert(file_offset <= _stat.st_size);
  return static_cast<const char*>(_mmap) + file_offset;
}

size_t File::size() const {
  return _stat.st_size;
}

int File::openat() {
  return _fd;
}

int File::fstat(struct stat* buf) {
  // Argument checking.
  if (!buf) [[unlikely]] {
    std::cerr << "Cannot fstat; output buffer not provided" << std::endl;
    return -1;
  }

  // Copy the cached stat structure back to the caller.
  // We assume that the stat structure will not have changed since the file will
  // not be written to and no other modifications will be allowed to it.
  std::memcpy(buf, &_stat, sizeof(struct stat));

  return 0;
}

off_t File::lseek(off_t offset, int whence) {
  std::lock_guard<decltype(_mutex)> lock(_mutex);

  // Make sure this operation is not being performed on a directory as this
  // does not make sense.
  if (_is_dir) {
    std::cerr << "Cannot lseek; directory: " << _file_path << std::endl;
    return -1;
  }

  // Argument checking.
  if (whence != SEEK_CUR) [[unlikely]] {
    std::cerr << "Cannot lseek; unsupported whence: " << whence << std::endl;
    return -1;
  }

  // Compute the new offset where the caller wants to seek to.
  const size_t new_offset = _offset + offset;

  // Ensure that the new offset does not overrun the file size;
  if (new_offset >= _stat.st_size) [[unlikely]] {
    std::cerr << "Cannot seek past the file size: (" << new_offset << " > "
              << _stat.st_size << ")" << std::endl;
    return -1;
  }

  // Update the offset for this file.
  _offset = new_offset;

  return _offset;
}

ssize_t File::read(void* buf, size_t count) {
  std::lock_guard<decltype(_mutex)> lock(_mutex);

  // Make sure this operation is not being performed on a directory as this does
  // not make sense.
  if (_is_dir) {
    std::cerr << "Cannot read; directory: " << _file_path << std::endl;
    return -1;
  }

  // Argument checking.
  if (count == 0) [[unlikely]] {
    return 0;
  }

  // Argument checking.
  if (!buf) [[unlikely]] {
    std::cerr << "Cannot read; output buffer not provided" << std::endl;
    return -1;
  }

  // Compute the maximum number of bytes that are remaining to be read relative
  // to the current offset and the total file size.
  const size_t max_readable_bytes = _stat.st_size - _offset;

  // Check if there is any data to read.
  if (max_readable_bytes == 0) {
    return 0;
  }

  // Clip the maximum possible bytes that can be read, if needed.
  if (count > max_readable_bytes) {
    count = max_readable_bytes;
  }

  assert(_mmap);

  // Calculate where to start reading from and copy from that location onwards
  // into the caller provided buffer.
  const void* src = static_cast<const char*>(_mmap) + _offset;
  std::memcpy(buf, src, count);

  // Update the offset for this file.
  _offset += count;

  return count;
}

ssize_t File::write(const void* buf, size_t count) {
  std::lock_guard<decltype(_mutex)> lock(_mutex);

  spdlog::warn("Unsupported operation: write");
  return -1;
}

int File::close() {
  std::lock_guard<decltype(_mutex)> lock(_mutex);

  // TODO(gohar): We need to figure out what can be done in the close path.
  // If we munmap the _mmap, then we won't be able to mmap it again (as it was
  // mmaped earlier when we did not enter protected mode). Can we use something
  // like ftruncate to clear up the memory and fault it again upon subsequent
  // accesses?
  return 0;
}

int File::_mmap_no_lock() {
  // Directories were never mapped so ignore this.
  if (_is_dir) {
    return 0;
  }

  // Already mapped, nothing to do.
  if (_mmap) {
    return 0;
  }

  // Always mmap from the beginning.
  auto res = syscall_no_intercept(SYS_mmap, nullptr /* addr */, _stat.st_size,
    PROT, FLAGS, _fd, 0);
  {
    const int err = syscall_error_code(res);
    if (err != 0) {
      spdlog::error("Cannot mmap: {0}", strerror(err));
      return err;
    }
  }

  // Error checking.
  void* mmap = reinterpret_cast<void*>(res);
  if (mmap == MAP_FAILED) [[unlikely]] {
    std::cerr << "Cannot create file; unable to mmap: " << _fd << ", "
              << _file_path << std::endl;
    perror("mmap");
    return -1;
  }

  _mmap = mmap;

  return 0;
}

int File::_munmap_no_lock() {
  // If not currently mapped, nothing to do.
  if (!_mmap) [[unlikely]] {
    return 0;
  }

  auto res = syscall_no_intercept(SYS_munmap, _mmap, _stat.st_size);
  {
    const int err = syscall_error_code(res);
    if (err != 0) {
      spdlog::error("Cannot munmap: {0}", strerror(err));
      return err;
    }
  }

  // Reset the state for this file.
  _offset = 0;
  _mmap = nullptr;

  return res;
}

}  // namespace junction