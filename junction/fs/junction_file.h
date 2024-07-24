// junction_file.h - convenience class that allows the Junction kernel to
// interact with files in the filesystem.

#pragma once

#include "junction/fs/file.h"
#include "junction/fs/fs.h"
#include "junction/kernel/mm.h"

namespace junction {

class MemoryMap;
class FSRoot;

// JunctionFile provides a wrapper around a Junction FS-provided file.
class JunctionFile {
 public:
  // Open creates a new file descriptor attached to a file path.
  static Status<JunctionFile> Open(FSRoot &fs, std::string_view path, int flags,
                                   FileMode mode) {
    Status<std::shared_ptr<DirectoryEntry>> in = LookupDirEntry(fs, path);
    if (!in) return MakeError(in);

    Status<std::shared_ptr<File>> f = (*in)->Open(flags, mode);
    if (!f) return MakeError(f);
    return JunctionFile(std::move(*f));
  }

  explicit JunctionFile(std::shared_ptr<File> &&f) noexcept
      : f_(std::move(f)) {}
  ~JunctionFile() = default;

  // Read from the file.
  Status<size_t> Read(std::span<std::byte> buf) { return f_->Read(buf, &off_); }

  // Write to the file.
  Status<size_t> Write(std::span<const std::byte> buf) {
    return f_->Write(buf, &off_);
  }

  // Map a portion of the file.
  Status<void *> MMap(MemoryMap &mm, size_t length, int prot, int flags,
                      off_t off) {
    assert(!(flags & (MAP_FIXED | MAP_ANONYMOUS)));
    flags |= MAP_PRIVATE;
    return mm.MMap(nullptr, length, prot, flags, f_, off);
  }

  // Map a portion of the file to a fixed address.
  Status<void> MMapFixed(MemoryMap &mm, void *addr, size_t length, int prot,
                         int flags, off_t off) {
    assert(!(flags & MAP_ANONYMOUS));
    flags |= MAP_FIXED | MAP_PRIVATE;
    Status<void *> ret = mm.MMap(addr, length, prot, flags, f_, off);
    if (!ret) return MakeError(ret);
    return {};
  }

  // Seek to a different position in the file.
  Status<void> Seek(off_t offset) {
    Status<off_t> ret = f_->Seek(offset, SeekFrom::kStart);
    if (!ret) return MakeError(ret);
    off_ = *ret;
    return {};
  }

 private:
  std::shared_ptr<File> f_;
  off_t off_{0};
};

}  // namespace junction