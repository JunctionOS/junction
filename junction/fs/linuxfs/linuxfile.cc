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
  assert(dynamic_cast_guarded<LinuxInode *>(&get_dent_ref().get_inode_ref()));
  f.Release();
}

LinuxFile::~LinuxFile() {
  if (fd_ != -1) ksys_close(fd_);
}

[[nodiscard]] size_t LinuxFile::get_size() const {
  if constexpr (!linux_fs_writeable()) {
    const LinuxInode &ino = static_cast<const LinuxInode &>(get_inode_ref());
    return ino.get_size();
  }
  struct stat buf;
  if (unlikely(fd_ == -1)) const_cast<LinuxFile *>(this)->EnableFd();
  int ret = ksys_newfstatat(fd_, "", &buf, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
  if (unlikely(ret < 0)) LinuxFSPanic("bad stat", Error(-ret));
  return buf.st_size;
}

Status<size_t> __attribute__((cold))
TraceLinuxRead(int fd, std::span<std::byte> buf, off_t *off) {
  // Read one page at a time during tracing.
  off_t loff = *off;
  size_t read = 0;
  while (buf.size()) {
    size_t to_read = std::min(
        buf.size(), PageAlign(reinterpret_cast<uintptr_t>(buf.data()) + 1) -
                        reinterpret_cast<uintptr_t>(buf.data()));

    // Touch the page before reading into it.
    volatile char *data = reinterpret_cast<volatile char *>(buf.data());
    volatile char c;
    c = access_once(*data);
    *data = c;

    ssize_t ret = ksys_pread(fd, buf.data(), to_read, loff);
    if (ret < 0) {
      // If there is an error, we can bail without updating *off.
      if (ret == -EINTR) return MakeError(ERESTARTSYS);
      return MakeError(-ret);
    }

    loff += ret;
    read += ret;
    if (static_cast<size_t>(ret) < to_read) break;
    buf = buf.subspan(to_read);
  }

  *off = loff;
  return read;
}

Status<size_t> LinuxFile::Read(std::span<std::byte> buf, off_t *off) {
  // If we are tracing page accesses, we need to fault the pages in before
  // passing them to the kernel since the page fault handler won't be invoked
  // by the kernel in this case.
  // TODO(jf): consider gating this with a compile flag.
  CheckFd();
  if (IsJunctionThread() && unlikely(myproc().get_mem_map().TraceEnabled()))
    return TraceLinuxRead(fd_, buf, off);
  ssize_t ret = ksys_pread(fd_, buf.data(), buf.size_bytes(), *off);
  if (ret < 0) {
    if (ret == -EINTR) return MakeError(ERESTARTSYS);
    return MakeError(-ret);
  }
  *off += ret;
  return ret;
}

Status<size_t> LinuxFile::Write(std::span<const std::byte> buf, off_t *off) {
  CheckFd();
  ssize_t ret = ksys_pwrite(fd_, buf.data(), buf.size_bytes(), *off);
  if (ret < 0) return MakeError(-ret);
  *off += ret;
  return ret;
}

Status<void *> LinuxFile::MMap(void *addr, size_t length, int prot, int flags,
                               off_t off) {
  CheckFd();
  assert(!(flags & MAP_ANONYMOUS));
  intptr_t ret = ksys_mmap(addr, length, prot, flags, fd_, off);
  if (ret < 0) return MakeError(-ret);
  return reinterpret_cast<void *>(ret);
}

}  // namespace junction::linuxfs

CEREAL_REGISTER_TYPE(junction::linuxfs::LinuxFile);
