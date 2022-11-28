extern "C" {
#include <sys/stat.h>
}

#include <syscall.h>

#include <string>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/filesystem/linuxfile.hpp"
#include "junction/kernel/ksys.h"

namespace junction {

std::shared_ptr<LinuxFile> LinuxFile::Open(const std::string_view &pathname,
                                           int flags, mode_t mode) {
  int fd = ksys_open(pathname.data(), flags, mode);
  if (fd < 0) return nullptr;
  return std::make_shared<MakeSharedEnabler>(fd, flags, mode);
}

LinuxFile::LinuxFile(int fd, int flags, mode_t mode) : fd_(fd) {
  flags_ = flags;
  mode_ = mode;
}

LinuxFile::~LinuxFile() {}

Status<size_t> LinuxFile::Read(std::span<std::byte> buf, off_t *off) {
  ssize_t ret = ksys_pread(fd_, buf.data(), buf.size_bytes(), *off);
  if (ret <= 0) return MakeError(-ret);
  *off += ret;
  return ret;
}

Status<size_t> LinuxFile::Write(std::span<const std::byte> buf, off_t *off) {
  ssize_t ret = ksys_pwrite(fd_, buf.data(), buf.size_bytes(), *off);
  if (ret < 0) return MakeError(-ret);
  *off += ret;
  return ret;
}

Status<off_t> LinuxFile::Seek(off_t off, SeekFrom origin) {
  if (origin == SeekFrom::kStart)
    return off;
  else if (origin == SeekFrom::kCurrent)
    return off_ + off;
  else
    return MakeError(EINVAL);
}

Status<void *> LinuxFile::MMap(void *addr, size_t length, int prot, int flags,
                               off_t off) {
  assert(!(flags & (MAP_FIXED | MAP_ANONYMOUS)));
  intptr_t ret = ksys_mmap(addr, length, prot, flags, fd_, off);
  if (ret < 0) return MakeError(-ret);
  return reinterpret_cast<void *>(ret);
}

Status<int> LinuxFile::Stat(struct stat *statbuf, int flags) {
  // For passing an empty string without initializing it each time.
  const static std::string empty;

  assert(flags & AT_EMPTY_PATH);
  int ret = ksys_newfstatat(fd_, empty.c_str() /* pathname */, statbuf, flags);
  if (ret < 0) return MakeError(-ret);
  return ret;
}

Status<int> LinuxFile::GetDents(void *dirp, unsigned int count) {
  int ret = ksys_getdents(fd_, dirp, count);
  if (ret < 0) return MakeError(-ret);
  return ret;
}

Status<int> LinuxFile::GetDents64(void *dirp, unsigned int count) {
  int ret = ksys_getdents64(fd_, dirp, count);
  if (ret < 0) return MakeError(-ret);
  return ret;
}

}  // namespace junction
