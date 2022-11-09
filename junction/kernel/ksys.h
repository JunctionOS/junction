#pragma once

extern "C" {
#include <stdlib.h>
}

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
void* ksys_mmap(void *addr, size_t length, int prot, int flags, int fd,
                off_t offset);
int ksys_munmap(void *addr, size_t length);
int ksys_mprotect(void *addr, size_t len, int prot);
int ksys_madvise(void *addr, size_t length, int advice);
int ksys_open(const char *pathname, int flags, mode_t mode);
ssize_t ksys_read(int fd, void *buf, size_t count);
ssize_t ksys_write(int fd, const void *buf, size_t count);
ssize_t ksys_pread(int fd, void *buf, size_t count, off_t offset);
ssize_t ksys_pwrite(int fd, const void *buf, size_t count, off_t offset);
void ksys_exit(int status) __attribute__((noreturn));
}

// KernelFileReader provides a wrapper around a Linux FD for reading.
class KernelFileReader {
 public:
  explicit KernelFileReader(int fd) noexcept : fd_(fd) {}
  ~KernelFileReader() = default;

  // disable copy.
  KernelFileReader(const KernelFileReader &) = delete;
  KernelFileReader &operator=(const KernelFileReader &) = delete;

  // allow move.
  KernelFileReader(KernelFileReader &&f) noexcept : fd_(f.fd_), off_(f.off_) {
    f.fd_ = -1;
    f.off_ = 0;
  }
  KernelFileReader &operator=(KernelFileReader &&f) noexcept {
    fd_ = std::exchange(f.fd_, -1);
    off_ = std::exchange(f.off_, 0);
    return *this;
  }

  Status<size_t> Read(std::span<std::byte> buf) {
    ssize_t ret = ksys_pread(fd_, buf.data(), buf.size_bytes(), off_);
    if (ret <= 0) return MakeError(static_cast<int>(-ret));
    off_ += ret;
    return ret;
  }

  void Seek(off_t offset) { off_ = offset; }

 private:
  int fd_;
  off_t off_{0};
};

}  // namespace junction
