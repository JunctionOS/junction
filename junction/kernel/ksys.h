#pragma once

extern "C" {
#include <sys/mman.h>
}

#include <cstddef>
#include <cstdlib>
#include <span>
#include <utility>

#include "junction/base/error.h"

namespace junction {

// Available Linux Kernel System Calls (after seccomp_filter is enabled)
extern "C" {
extern long ksys_start;
extern long ksys_end;
// TODO(girfan): We need to eventually remove ksys_default.
long ksys_default(long sys_num, ...);
intptr_t ksys_mmap(void *addr, size_t length, int prot, int flags, int fd,
                   off_t offset);
int ksys_munmap(void *addr, size_t length);
int ksys_mprotect(void *addr, size_t len, int prot);
int ksys_madvise(void *addr, size_t length, int advice);
int ksys_open(const char *pathname, int flags, mode_t mode);
int ksys_close(int fd);
ssize_t ksys_read(int fd, void *buf, size_t count);
ssize_t ksys_write(int fd, const void *buf, size_t count);
ssize_t ksys_pread(int fd, void *buf, size_t count, off_t offset);
ssize_t ksys_pwrite(int fd, const void *buf, size_t count, off_t offset);
void ksys_exit(int status) __attribute__((noreturn));
}

// KernelFile provides a wrapper around a Linux FD.
class KernelFile {
 public:
  // Open creates a new file descriptor attached to a file path.
  static Status<KernelFile> Open(std::string_view path, int flags,
                                 mode_t mode) {
    int ret = ksys_open(path.data(), flags, mode);
    if (ret < 0) return MakeError(-ret);
    return KernelFile(ret);
  }

  KernelFile() noexcept = default;
  explicit KernelFile(int fd) noexcept : fd_(fd) {}
  ~KernelFile() {
    if (fd_ >= 0) ksys_close(fd_);
  }

  // disable copy.
  KernelFile(const KernelFile &) = delete;
  KernelFile &operator=(const KernelFile &) = delete;

  // allow move.
  KernelFile(KernelFile &&f) noexcept
      : fd_(std::exchange(f.fd_, -1)), off_(std::exchange(f.off_, 0)) {}
  KernelFile &operator=(KernelFile &&f) noexcept {
    fd_ = std::exchange(f.fd_, -1);
    off_ = std::exchange(f.off_, 0);
    return *this;
  }

  // Read from the file.
  Status<size_t> Read(std::span<std::byte> buf) {
    ssize_t ret = ksys_pread(fd_, buf.data(), buf.size_bytes(), off_);
    if (ret <= 0) return MakeError(static_cast<int>(-ret));
    off_ += ret;
    return static_cast<size_t>(ret);
  }

  // Write to the file.
  Status<size_t> Write(std::span<const std::byte> buf) {
    ssize_t ret = ksys_pwrite(fd_, buf.data(), buf.size_bytes(), off_);
    if (ret < 0) return MakeError(static_cast<int>(-ret));
    off_ += ret;
    return static_cast<size_t>(ret);
  }

  // Map a portion of the file.
  Status<void *> MMap(size_t length, int prot, int flags, off_t off) {
    assert(!(flags & (MAP_FIXED | MAP_ANONYMOUS)));
    flags |= MAP_PRIVATE;
    intptr_t ret = ksys_mmap(nullptr, length, prot, flags, fd_, off);
    if (ret < 0) return MakeError(-ret);
    return reinterpret_cast<void *>(ret);
  }

  // Map a portion of the file to a fixed address.
  Status<void> MMapFixed(void *addr, size_t length, int prot, int flags,
                         off_t off) {
    assert(!(flags & MAP_ANONYMOUS));
    flags |= MAP_FIXED | MAP_PRIVATE;
    intptr_t ret = ksys_mmap(addr, length, prot, flags, fd_, off);
    if (ret < 0) return MakeError(-ret);
    assert(reinterpret_cast<void *>(ret) == addr);
    return {};
  }

  // Seek to a different position in the file.
  void Seek(off_t offset) { off_ = offset; }

 private:
  int fd_{-1};
  off_t off_{0};
};

// Map anonymous memory.
inline Status<void *> KernelMMap(size_t length, int prot, int flags) {
  flags |= MAP_ANONYMOUS | MAP_PRIVATE;
  intptr_t ret = ksys_mmap(nullptr, length, prot, flags, -1, 0);
  if (ret < 0) return MakeError(-ret);
  return reinterpret_cast<void *>(ret);
}

// Map anonymous memory to a fixed address.
inline Status<void> KernelMMapFixed(void *addr, size_t length, int prot,
                                    int flags) {
  flags |= MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE;
  intptr_t ret = ksys_mmap(addr, length, prot, flags, -1, 0);
  if (ret < 0) return MakeError(-ret);
  assert(reinterpret_cast<void *>(ret) == addr);
  return {};
}

// Unmap memory.
inline Status<void> KernelUnmap(void *addr, size_t length) {
  int ret = ksys_munmap(addr, length);
  if (ret < 0) return MakeError(-ret);
  return {};
}

inline Status<void> KernelMProtect(void *addr, size_t length, int prot) {
  int ret = ksys_mprotect(addr, length, prot);
  if (ret < 0) return MakeError(-ret);
  return {};
}

}  // namespace junction
