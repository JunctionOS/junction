#include "junction/kernel/stdiofile.h"

#include <syscall.h>

#include <string>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/kernel/ksys.h"

namespace junction {

StdIOFile::StdIOFile(int fd, unsigned int mode) : fd_(fd) { mode_ = mode; }

StdIOFile::~StdIOFile() {}

Status<size_t> StdIOFile::Read(std::span<std::byte> buf, off_t *off) {
  long ret = ksys_read(fd_, buf.data(), buf.size_bytes());
  if (ret <= 0) return MakeError(-ret);
  *off = ret;
  return ret;
}

Status<size_t> StdIOFile::Write(std::span<const std::byte> buf, off_t *off) {
  long ret = ksys_write(fd_, buf.data(), buf.size_bytes());
  if (ret < 0) return MakeError(-ret);
  *off = ret;
  return ret;
}

Status<int> StdIOFile::Stat(struct stat *statbuf, int flags) {
  // For passing an empty string without initializing it each time.
  const static std::string empty;

  assert(flags & AT_EMPTY_PATH);
  int ret = ksys_newfstatat(fd_, empty.c_str() /* pathname */, statbuf, flags);
  if (ret < 0) return MakeError(-ret);
  return ret;
}

}  // namespace junction
