extern "C" {
#include <sys/stat.h>
}

#include <syscall.h>

#include <memory>
#include <string>

#include "junction/base/error.h"
#include "junction/fs/linuxfs/linuxfile.h"
#include "junction/fs/linuxfs/linuxfs.h"
#include "junction/kernel/ksys.h"
#include "junction/snapshot/cereal.h"
#include "junction/syscall/strace.h"

namespace junction::linuxfs {

LinuxFile::LinuxFile(KernelFile &&f, int flags, FileMode mode,
                     std::shared_ptr<DirectoryEntry> dent) noexcept
    : SeekableFile(FileType::kNormal, flags, mode, std::move(dent)),
      fd_(f.GetFd()) {
  assert(dynamic_cast<LinuxInode *>(&get_dent_ref().get_inode_ref()));
  f.Release();
}

LinuxFile::~LinuxFile() { ksys_close(fd_); }

[[nodiscard]] size_t LinuxFile::get_size() const {
  struct stat buf;
  int ret = ksys_newfstatat(fd_, "", &buf, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
  if (unlikely(ret < 0)) LinuxFSPanic("bad stat", Error(-ret));
  return buf.st_size;
}

void TouchPages(std::span<std::byte> buf) {
  uintptr_t start = PageAlignDown(reinterpret_cast<uintptr_t>(buf.data()));
  char *pg = reinterpret_cast<char *>(start);
  char *end = reinterpret_cast<char *>(buf.data() + buf.size_bytes());
  [[maybe_unused]] volatile char c;
  for (; pg < end; pg += kPageSize) c = access_once(*pg);
}

Status<size_t> LinuxFile::Read(std::span<std::byte> buf, off_t *off) {
  // If we are tracing page accesses, we need to fault the pages in before
  // passing them to the kernel since the page fault handler won't be invoked
  // by the kernel in this case.
  // TODO(jf): consider gating this with a compile flag.
  if (IsJunctionThread() && unlikely(myproc().get_mem_map().TraceEnabled()))
    TouchPages(buf);
  ssize_t ret = ksys_pread(fd_, buf.data(), buf.size_bytes(), *off);
  if (ret < 0) {
    if (ret == -EINTR) return MakeError(ERESTARTSYS);
    return MakeError(-ret);
  }
  *off += ret;
  return ret;
}

Status<size_t> LinuxFile::Write(std::span<const std::byte> buf, off_t *off) {
  ssize_t ret = ksys_pwrite(fd_, buf.data(), buf.size_bytes(), *off);
  if (ret < 0) return MakeError(-ret);
  *off += ret;
  return ret;
}

Status<void *> LinuxFile::MMap(void *addr, size_t length, int prot, int flags,
                               off_t off) {
  assert(!(flags & MAP_ANONYMOUS));
  intptr_t ret = ksys_mmap(addr, length, prot, flags, fd_, off);
  if (ret < 0) return MakeError(-ret);
  return reinterpret_cast<void *>(ret);
}

}  // namespace junction::linuxfs

CEREAL_REGISTER_TYPE(junction::linuxfs::LinuxFile);
