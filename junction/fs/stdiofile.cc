extern "C" {
#include <syscall.h>
#include <unistd.h>
}

#include <string>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/fs/fs.h"
#include "junction/fs/stdiofile.h"
#include "junction/kernel/ksys.h"

namespace junction {

// TODO(gohar): set file flags here too instead of 0
StdIOFile::StdIOFile(unsigned int flags, FileMode mode,
                     std::shared_ptr<DirectoryEntry> dent)
    : File(FileType::kNormal, flags, mode, std::move(dent)) {}

Status<size_t> StdIOFile::Read(std::span<std::byte> buf, off_t *off) {
  long ret = ksys_read(kStdInFileNo, buf.data(), buf.size_bytes());
  if (ret < 0) return MakeError(-ret);
  *off = ret;
  return ret;
}

Status<size_t> StdIOFile::Write(std::span<const std::byte> buf, off_t *off) {
  long ret = ksys_write(kStdOutFileNo, buf.data(), buf.size_bytes());
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

void StdIOFile::save(cereal::BinaryOutputArchive &ar) const {
  Status<std::string> ret = get_dent_ref().GetPathStr();
  if (!ret) throw std::runtime_error("stale linuxfile handle");
  ar(get_flags(), get_mode(), *ret);
  ar(cereal::base_class<File>(this));
}

void StdIOFile::load_and_construct(cereal::BinaryInputArchive &ar,
                                   cereal::construct<StdIOFile> &construct) {
  int flags;
  FileMode mode;
  std::string path;
  ar(flags, mode, path);
  Status<std::shared_ptr<DirectoryEntry>> ret =
      LookupDirEntry(FSRoot::GetGlobalRoot(), path);
  if (unlikely(!ret))
    throw std::runtime_error("bad lookup on linuxfile restore");
  construct(flags, mode, std::move(*ret));
  ar(cereal::base_class<File>(construct.ptr()));
}

}  // namespace junction
