extern "C" {
#include <syscall.h>
#include <unistd.h>
}

#include <string>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/stdiofile.h"

namespace junction {

// TODO(gohar): set file flags here too instead of 0
StdIOFile::StdIOFile(int fd, unsigned int mode)
    : File(FileType::kNormal, 0, mode), fd_(fd) {}

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

Status<void> StdIOFile::Stat(struct stat *statbuf, int flags) {
  char empty_path[1] = {'\0'};
  assert(flags & AT_EMPTY_PATH);
  int ret = ksys_newfstatat(fd_, empty_path /* pathname */, statbuf, flags);
  if (ret) return MakeError(-ret);
  return {};
}

Status<void> StdIOFile::Sync() {
  //  int ret = fsync(fd_);
  //  if (ret) return MakeError(-ret);
  return {};
}

}  // namespace junction
