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

// KernelExtent tracks the lifetime of a memory mapping.
class KernelExtent {
 public:
  KernelExtent() = default;
  KernelExtent(void *buf, size_t len) : base_(buf), len_(len) {}
  ~KernelExtent() { if (base_) ksys_munmap(base_, len_); }

  // disable copy.
  KernelExtent(const KernelExtent &) = delete;
  KernelExtent &operator=(const KernelExtent &) = delete;

  // allow move.
  KernelExtent(KernelExtent &&e) noexcept : base_(e.base_), len_(e.len_) {
    e.base_ = nullptr;
  }
  KernelExtent &operator=(KernelExtent &&e) noexcept {
    std::swap(base_, e.base_);
    len_ = e.len_;
    return *this;
  }

  [[nodiscard]] void *get_base() const { return base_; }
  [[nodiscard]] size_t get_length() const { return len_; }

 private:
  void *base_{nullptr};
  size_t len_;
};

// KernelFile provides a wrapper around a Linux FD.
class KernelFile {
 public:
  // Open creates a new file descriptor attached to a file path.
  static Status<KernelFile> Open(std::string_view path, int flags, mode_t mode) {
    int ret = ksys_open(path.data(), flags, mode);
    if (ret < 0) return MakeError(-ret);
    return KernelFile(ret);
  }

  KernelFile() noexcept = default;
  explicit KernelFile(int fd) noexcept : fd_(fd) {}
  ~KernelFile() { if (fd_ >= 0) ksys_close(fd_); }

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
  Status<KernelExtent> MMap(size_t length, int prot, int flags, off_t off) {
    assert(!(flags & (MAP_FIXED | MAP_ANONYMOUS)));
    intptr_t ret = ksys_mmap(nullptr, length, prot, flags, fd_, off);
    if (ret < 0) return MakeError(-ret);
    return KernelExtent(reinterpret_cast<void*>(ret), length);
  }

  // Map a portion of the file to a fixed address.
  Status<KernelExtent> MMapFixed(void *addr, size_t length, int prot, int flags,
                                 off_t off) {
    assert(!(flags & MAP_ANONYMOUS));
    flags |= MAP_FIXED;
    intptr_t ret = ksys_mmap(addr, length, prot, flags, fd_, off);
    if (ret < 0) return MakeError(-ret);
    return KernelExtent(reinterpret_cast<void*>(ret), length);

  }

  // Seek to a different position in the file.
  void Seek(off_t offset) { off_ = offset; }

 private:
  int fd_{-1};
  off_t off_{0};
};

// Map anonymous memory.
Status<KernelExtent> MMapAnonymous(size_t length, int prot, int flags) {
  flags |= MAP_ANONYMOUS;
  intptr_t ret = ksys_mmap(nullptr, length, prot, flags, -1, 0);
  if (ret < 0) return MakeError(-ret);
  return KernelExtent(reinterpret_cast<void*>(ret), length);
}

// Map anonymous memory to a fixed address.
Status<KernelExtent> MMapAnonymousFixed(void *addr, size_t length, int prot,
                                        int flags) {
  flags |= MAP_ANONYMOUS | MAP_FIXED;
  intptr_t ret = ksys_mmap(addr, length, prot, flags, -1, 0);
  if (ret < 0) return MakeError(-ret);
  return KernelExtent(reinterpret_cast<void*>(ret), length);
}

}  // namespace junction
