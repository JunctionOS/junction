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
StdIOFile::StdIOFile(int fd, FileMode mode)
    : File(FileType::kNormal, 0, mode), fd_(fd) {}

StdIOFile::~StdIOFile() {}

Status<size_t> StdIOFile::Read(std::span<std::byte> buf, off_t *off) {
  long ret = ksys_read(fd_, buf.data(), buf.size_bytes());
  if (ret < 0) return MakeError(-ret);
  *off = ret;
  return ret;
}

Status<size_t> StdIOFile::Write(std::span<const std::byte> buf, off_t *off) {
  long ret = ksys_write(fd_, buf.data(), buf.size_bytes());
  if (ret < 0) return MakeError(-ret);
  *off = ret;
  return ret;
}

Status<void> StdIOFile::Stat(struct stat *statbuf) const {
  memset(statbuf, 0, sizeof(*statbuf));
  statbuf->st_mode = S_IFCHR | S_IRUSR | S_IWUSR;
  return {};
}

Status<void> StdIOFile::Sync() {
  //  int ret = fsync(fd_);
  //  if (ret) return MakeError(-ret);
  return {};
}

}  // namespace junction
