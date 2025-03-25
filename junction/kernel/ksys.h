#pragma once

extern "C" {
#include <base/syscall.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
}

#include <cstddef>
#include <cstdlib>
#include <span>
#include <utility>

#include "junction/base/error.h"
#include "junction/base/io.h"
#include "junction/fs/file.h"

namespace junction {

inline constexpr int kMaxIovLen = 1024;  // Linux's max.

#ifdef WRITEABLE_LINUX_FS
constexpr bool linux_fs_writeable() { return true; }
#else
constexpr bool linux_fs_writeable() { return false; }
#endif

// VDSO syscalls
extern int (*ksys_clock_gettime)(clockid_t clockid, struct timespec *tp);

// Available Linux Kernel System Calls (after seccomp_filter is enabled)
extern "C" {
extern long ksys_start;
extern long ksys_end;
// TODO(girfan): We need to eventually remove ksys_default.
long ksys_default(long arg0, long arg1, long arg2, long arg3, long arg4,
                  long arg5, long sys_num);
intptr_t ksys_mmap(void *addr, size_t length, int prot, int flags, int fd,
                   off_t offset);
intptr_t ksys_mremap(void *oldaddr, size_t oldsz, size_t newsz, int flags,
                     void *new_addr);
int ksys_munmap(void *addr, size_t length);
int ksys_mprotect(void *addr, size_t len, int prot);
long ksys_madvise(void *addr, size_t length, int advice);
int ksys_openat(int fd, const char *pathname, int flags, mode_t mode);
int ksys_close(int fd);
ssize_t ksys_pread(int fd, void *buf, size_t count, off_t offset);
int ksys_tgkill(pid_t tgid, pid_t tid, int sig);
ssize_t ksys_readlinkat(int dirfd, const char *pathname, char *buf,
                        size_t bufsz);

static inline int ksys_open(const char *pathname, int flags, mode_t mode) {
  return ksys_openat(AT_FDCWD, pathname, flags, mode);
}

static inline ssize_t ksys_write(int fd, const void *buf, size_t count) {
  return syscall_write(fd, buf, count);
}

#if 0
ssize_t ksys_readv(int fd, const struct iovec *iov, int iovcnt);

static inline ssize_t ksys_read(int fd, void *buf, size_t count) {
  iovec v = {.iov_base = buf, .iov_len = count};
  return ksys_readv(fd, &v, 1);
}
#endif

static inline ssize_t ksys_pwritev(int fd, const struct iovec *iov, int iovcnt,
                                   off_t offset) {
  iovcnt = std::min(kMaxIovLen, iovcnt);
  return syscall_pwritev2(fd, iov, iovcnt, offset, 0, 0);
}
static inline ssize_t ksys_pwrite(int fd, const void *buf, size_t count,
                                  off_t offset) {
  const struct iovec iov = {.iov_base = (void *)buf, .iov_len = count};
  return ksys_pwritev(fd, &iov, 1, offset);
}
int ksys_newfstatat(int dirfd, const char *pathname, struct stat *statbuf,
                    int flags);
int ksys_getdents64(unsigned int fd, void *dirp, unsigned int count);
void ksys_exit(int status) __attribute__((noreturn));
}

template <class T>
concept SyscallArg = std::is_convertible_v<T, long> || std::is_pointer_v<T>;

template <typename A, typename B, typename C, typename D, typename E,
          typename F>
  requires SyscallArg<A> && SyscallArg<B> && SyscallArg<C> && SyscallArg<D> &&
           SyscallArg<E> && SyscallArg<F>
static __always_inline long ksyscall(int sysnr, A arg1, B arg2, C arg3, D arg4,
                                     E arg5, F arg6) {
  return ksys_default((long)arg1, (long)arg2, (long)arg3, (long)arg4,
                      (long)arg5, (long)arg6, sysnr);
}

template <typename A, typename B, typename C, typename D, typename E>
static __always_inline long ksyscall(int sysnr, A arg1, B arg2, C arg3, D arg4,
                                     E arg5) {
  register long arg6 asm("r9");
  return ksyscall(sysnr, arg1, arg2, arg3, arg4, arg5, arg6);
}

template <typename A, typename B, typename C, typename D>
static __always_inline long ksyscall(int sysnr, A arg1, B arg2, C arg3,
                                     D arg4) {
  register long arg5 asm("r8");
  return ksyscall(sysnr, arg1, arg2, arg3, arg4, arg5);
}

template <typename A, typename B, typename C>
static __always_inline long ksyscall(int sysnr, A arg1, B arg2, C arg3) {
  register long arg4 asm("rcx");
  return ksyscall(sysnr, arg1, arg2, arg3, arg4);
}

template <typename A, typename B>
static __always_inline long ksyscall(int sysnr, A arg1, B arg2) {
  register long arg3 asm("rdx");
  return ksyscall(sysnr, arg1, arg2, arg3);
}

template <typename A>
static __always_inline long ksyscall(int sysnr, A arg1) {
  register long arg2 asm("rsi");
  return ksyscall(sysnr, arg1, arg2);
}

static __always_inline long ksyscall(int sysnr) {
  register long arg1 asm("rdi");
  return ksyscall(sysnr, arg1);
}

// KernelFile provides a wrapper around a Linux FD.
class KernelFile : public VectoredWriter {
 public:
  // Open creates a new file descriptor attached to a file path.
  static Status<KernelFile> Open(std::string_view path, int flags,
                                 FileMode fmode, mode_t mode = 0) {
    int ret = ksys_open(path.data(), flags | ToFlags(fmode), mode);
    if (ret < 0) return MakeError(-ret);
    return KernelFile(ret);
  }

  // Open creates a new file descriptor attached to a file path.
  static Status<KernelFile> Open(const char *path, int flags, FileMode fmode,
                                 mode_t mode = 0) {
    int ret = ksys_open(path, flags | ToFlags(fmode), mode);
    if (ret < 0) return MakeError(-ret);
    return KernelFile(ret);
  }

  static Status<KernelFile> OpenAt(int fd, std::string_view path, int flags,
                                   FileMode fmode, mode_t mode = 0) {
    int ret = ksys_openat(fd, path.data(), flags | ToFlags(fmode), mode);
    if (ret < 0) return MakeError(-ret);
    return KernelFile(ret);
  }

  Status<KernelFile> OpenAt(std::string_view path, int flags, FileMode fmode,
                            mode_t mode = 0) {
    int ret = ksys_openat(fd_, path.data(), flags | ToFlags(fmode), mode);
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
    if (ret < 0) return MakeError(static_cast<int>(-ret));
    if (ret == 0) return MakeError(EUNEXPECTEDEOF);
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

  // Write to the file.
  Status<size_t> Writev(std::span<const iovec> iov) {
    ssize_t ret = ksys_pwritev(fd_, iov.data(), iov.size(), off_);
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

  inline Status<struct stat> StatAt() const {
    struct stat buf;
    int ret =
        ksys_newfstatat(fd_, "", &buf, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
    if (ret < 0) return MakeError(-ret);
    return buf;
  }

  inline Status<struct stat> StatAt(std::string_view path) {
    struct stat buf;
    int ret = ksys_newfstatat(fd_, path.data(), &buf, AT_SYMLINK_NOFOLLOW);
    if (ret < 0) return MakeError(-ret);
    return buf;
  }

  Status<void> UnlinkAt(std::string_view path, int flags = 0) {
    if constexpr (!linux_fs_writeable()) return MakeError(EACCES);
    int ret = ksyscall(__NR_unlinkat, fd_, path.data(), flags);
    if (ret < 0) return MakeError(-ret);
    return {};
  }

  Status<std::string_view> ReadLinkAt(std::string_view path,
                                      std::span<char> buf) {
    ssize_t wret = ksys_readlinkat(fd_, path.data(), buf.data(), buf.size());
    if (wret < 0) return MakeError(-wret);
    return {{buf.data(), static_cast<size_t>(wret)}};
  }

  Status<void> MkDirAt(std::string_view path, mode_t mode) {
    if constexpr (!linux_fs_writeable()) return MakeError(EACCES);
    int ret = ksyscall(__NR_mkdirat, fd_, path.data(), mode);
    if (ret < 0) return MakeError(-ret);
    return {};
  }

  Status<void> SymLinkAt(std::string_view target, std::string_view path) {
    if constexpr (!linux_fs_writeable()) return MakeError(EACCES);
    int ret = ksyscall(__NR_symlinkat, target.data(), fd_, path.data());
    if (ret < 0) return MakeError(-ret);
    return {};
  }

  static Status<void> RenameAt(KernelFile &olddir, std::string_view oldpath,
                               KernelFile &newdir, std::string_view newpath,
                               bool replace) {
    if constexpr (!linux_fs_writeable()) return MakeError(EACCES);
    int flags = replace ? 0 : RENAME_NOREPLACE;
    int ret = ksyscall(__NR_renameat2, olddir.fd_, oldpath.data(), newdir.fd_,
                       newpath.data(), flags);
    if (ret < 0) return MakeError(-ret);
    return {};
  }

  static Status<void> LinkAt(KernelFile &olddir, std::string_view oldpath,
                             KernelFile &newdir, std::string_view newpath) {
    if constexpr (!linux_fs_writeable()) return MakeError(EACCES);
    int ret = ksyscall(__NR_linkat, olddir.fd_, oldpath.data(), newdir.fd_,
                       newpath.data(), 0);
    if (ret < 0) return MakeError(-ret);
    return {};
  }

  // Seek to a different position in the file.
  void Seek(off_t offset) { off_ = offset; }
  [[nodiscard]] off_t Tell() const { return off_; }

  [[nodiscard]] int GetFd() const { return fd_; }
  void Release() { fd_ = -1; }

 private:
  int fd_{-1};
  off_t off_{0};
};

// Map anonymous memory.
inline Status<void *> KernelMMap(void *addr, size_t length, int prot,
                                 int flags) {
  flags |= MAP_ANONYMOUS | MAP_PRIVATE;
  intptr_t ret = ksys_mmap(addr, length, prot, flags, -1, 0);
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
inline Status<void> KernelMUnmap(void *addr, size_t length) {
  int ret = ksys_munmap(addr, length);
  if (ret < 0) return MakeError(-ret);
  return {};
}

// Change memory permissions.
inline Status<void> KernelMProtect(void *addr, size_t length, int prot) {
  int ret = ksys_mprotect(addr, length, prot);
  if (ret < 0) return MakeError(-ret);
  return {};
}

// Pass mapping hints.
inline Status<void> KernelMAdvise(void *addr, size_t length, int hint) {
  int ret = ksys_madvise(addr, length, hint);
  if (ret < 0) return MakeError(-ret);
  return {};
}

inline Status<void *> KernelMRemap(void *old_addr, size_t old_sz,
                                   size_t new_len, int flags,
                                   void *new_addr = nullptr) {
  intptr_t ret = ksys_mremap(old_addr, old_sz, new_len, flags, new_addr);
  if (ret < 0) return MakeError(-ret);
  return reinterpret_cast<void *>(ret);
}

// Get file status.
inline Status<void> KernelStat(const char *path, struct stat *buf) {
  int ret = ksys_newfstatat(AT_FDCWD, path, buf, 0);
  if (ret < 0) return MakeError(-ret);
  return {};
}

}  // namespace junction
