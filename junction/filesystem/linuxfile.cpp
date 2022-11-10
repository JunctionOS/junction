#include "junction/filesystem/linuxfile.hpp"

#include <syscall.h>

#include <string>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/kernel/ksys.h"

namespace junction {

LinuxFile::LinuxFile(const std::string_view &pathname, int flags, mode_t mode) {
  int fd = ksys_open(pathname.data(), flags, mode);
  if (fd < 0) {
    LOG(ERR) << "Cannot open: " << pathname;
    return;
  }

  fd_ = fd;
  flags_ = flags;
}

LinuxFile::~LinuxFile() {}

Status<size_t> LinuxFile::Read(std::span<std::byte> buf, off_t *off) {
  long ret = ksys_pread(fd_, buf.data(), buf.size_bytes(), *off);
  if (ret <= 0) return MakeError(-ret);
  *off += ret;
  return ret;
}

Status<size_t> LinuxFile::Write(std::span<const std::byte> buf, off_t *off) {
  long ret = ksys_pwrite(fd_, buf.data(), buf.size_bytes(), *off);
  if (ret < 0) return MakeError(-ret);
  *off += ret;
  return ret;
}

Status<off_t> LinuxFile::Seek(off_t off, SeekFrom origin) {
  return MakeError(EINVAL);
}

Status<void> LinuxFile::Sync() { return MakeError(EINVAL); }

}  // namespace junction
