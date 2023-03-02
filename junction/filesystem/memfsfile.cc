extern "C" {
#include <sys/stat.h>
}

#include <memory>
#include <string>
#include <string_view>

#include "junction/base/bits.h"
#include "junction/base/error.h"
#include "junction/filesystem/memfsfile.h"

namespace junction {

MemFSFile::MemFSFile(Token, const std::string_view &name, int flags,
                     mode_t mode,
                     const std::shared_ptr<MemFSInode> inode) noexcept
    : File(flags & kFlagDirectory ? FileType::kDirectory : FileType::kNormal,
           flags, mode),
      name_(name),
      inode_(inode) {}

std::shared_ptr<MemFSFile> MemFSFile::Open(
    const std::string_view &name, int flags, mode_t mode,
    const std::shared_ptr<MemFSInode> inode) {
  return std::make_shared<MemFSFile>(Token{}, name, flags, mode, inode);
}

Status<size_t> MemFSFile::Read(std::span<std::byte> buf, off_t *off) {
  auto ret = inode_->Read(buf, *off);
  if (ret) *off += *ret;
  return ret;
}

Status<size_t> MemFSFile::Write(std::span<const std::byte> buf, off_t *off) {
  auto ret = inode_->Write(buf, *off);
  if (ret) *off += *ret;
  return ret;
}

Status<void> MemFSFile::Truncate(off_t newlen) {
  return inode_->Truncate(newlen);
}

Status<void> MemFSFile::Allocate(int mode, off_t offset, off_t len) {
  return inode_->Allocate(mode, offset, len);
}

Status<off_t> MemFSFile::Seek(off_t off, SeekFrom origin) {
  if (origin == SeekFrom::kStart)
    return off;
  else if (origin == SeekFrom::kCurrent)
    return get_off_ref() + off;
  else
    return MakeError(EINVAL);
}

Status<void *> MemFSFile::MMap(void *addr, size_t length, int prot, int flags,
                               off_t off) {
  return MakeError(EINVAL);
}

Status<void> MemFSFile::Stat(struct stat *statbuf, [[maybe_unused]] int flags) {
  return inode_->Stat(statbuf);
}

Status<int> MemFSFile::GetDents(void *dirp, unsigned int count) {
  return inode_->GetDents(dirp, &count, &get_off_ref());
}

Status<int> MemFSFile::GetDents64(void *dirp, unsigned int count) {
  return MakeError(EINVAL);
}

}  // namespace junction
