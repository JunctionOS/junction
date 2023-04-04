extern "C" {
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
}

#include <algorithm>
#include <bit>
#include <memory>

#include "junction/base/io.h"
#include "junction/bindings/log.h"
#include "junction/kernel/file.h"
#include "junction/kernel/fs.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/stdiofile.h"
#include "junction/kernel/usys.h"

namespace {

constexpr size_t kInitialCap = 64;
constexpr size_t kOversizeRatio = 2;

}  // namespace

namespace junction {

namespace detail {

file_array::file_array(size_t cap)
    : cap(cap), files(std::make_unique<std::shared_ptr<File>[]>(cap)) {}

file_array::~file_array() = default;

std::unique_ptr<file_array> CopyFileArray(const file_array &src, size_t cap) {
  auto dst = std::make_unique<file_array>(cap);
  assert(src.len <= cap);
  std::copy_n(src.files.get(), src.len, dst->files.get());
  dst->len = src.len;
  return dst;
}

}  // namespace detail

FileTable::FileTable()
    : farr_(std::make_unique<FArr>(kInitialCap)), rcup_(farr_.get()) {
  // Create STDIN, STDOUT, STDERR files.
  std::shared_ptr<StdIOFile> fin =
      std::make_shared<StdIOFile>(kStdInFileNo, kModeRead);
  std::shared_ptr<StdIOFile> fout =
      std::make_shared<StdIOFile>(kStdOutFileNo, kModeWrite);
  std::shared_ptr<StdIOFile> ferr =
      std::make_shared<StdIOFile>(kStdErrFileNo, kModeWrite);
  Insert(std::move(fin));
  Insert(std::move(fout));
  Insert(std::move(ferr));
}

FileTable::~FileTable() = default;

void FileTable::Resize(size_t len) {
  assert(lock_.IsHeld());
  size_t new_cap = std::bit_ceil(len) * kOversizeRatio;
  if (farr_->cap < new_cap) {
    auto narr = detail::CopyFileArray(*farr_, new_cap);
    narr->len = len;
    rcup_.set(narr.get());
    rt::RCUFree(std::move(farr_));
    farr_ = std::move(narr);
  }
}

std::shared_ptr<File> FileTable::Dup(int fd) {
  rt::RCURead l;
  rt::RCUReadGuard g(l);
  const FArr *tbl = rcup_.get();
  if (unlikely(static_cast<size_t>(fd) >= tbl->len)) return {};
  return tbl->files[fd];
}

int FileTable::Insert(std::shared_ptr<File> f, size_t lowest) {
  rt::SpinGuard g(lock_);

  // Find the first empty slot to insert the file.
  size_t i;
  for (i = lowest; i < farr_->len; ++i) {
    if (!farr_->files[i]) {
      farr_->files[i] = std::move(f);
      return static_cast<int>(i);
    }
  }

  // Otherwise grow the table.
  Resize(i + 1);
  farr_->len = i + 1;
  farr_->files[i] = std::move(f);
  return static_cast<int>(i);
}

void FileTable::InsertAt(int fd, std::shared_ptr<File> f) {
  rt::SpinGuard g(lock_);
  if (static_cast<size_t>(fd) >= farr_->len) Resize(fd);
  farr_->files[fd] = std::move(f);
}

bool FileTable::Remove(int fd) {
  std::shared_ptr<File> tmp;  // so destructor is called without lock held
  {
    rt::SpinGuard g(lock_);

    // Check if the file is present.
    if (static_cast<size_t>(fd) >= farr_->len) return false;
    if (!farr_->files[fd]) return false;

    // Remove the file.
    tmp = std::move(farr_->files[fd]);
  }
  return true;
}

//
// System call implementations
//

void init_fs(FileSystem *fs) {
  // Set the filesystem.
  fs_.reset(fs);
}

long usys_open(const char *pathname, int flags, mode_t mode) {
  const std::string_view path(pathname);
  FileSystem *fs = get_fs();
  Status<std::shared_ptr<File>> f = fs->Open(path, mode, flags);
  if (unlikely(!f)) return -ENOENT;
  FileTable &ftbl = myproc().get_file_table();
  return ftbl.Insert(std::move(*f));
}

long usys_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
  if (unlikely(dirfd != AT_FDCWD)) return -EINVAL;
  return usys_open(pathname, flags, mode);
}

long usys_ftruncate(int fd, off_t length) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  auto ret = f->Truncate(length);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_fallocate(int fd, int mode, off_t offset, off_t len) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  auto ret = f->Allocate(mode, offset, len);
  if (!ret) return MakeCError(ret);
  return 0;
}

ssize_t usys_read(int fd, char *buf, size_t len) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeWrite)) return -EBADF;
  Status<size_t> ret = f->Read(readable_span(buf, len), &f->get_off_ref());
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_write(int fd, const char *buf, size_t len) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeRead)) return -EBADF;
  Status<size_t> ret = f->Write(writable_span(buf, len), &f->get_off_ref());
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_pread64(int fd, char *buf, size_t len, off_t offset) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeWrite)) return -EBADF;
  Status<size_t> ret = f->Read(readable_span(buf, len), &offset);
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

Status<size_t> File::Writev(std::span<const iovec> vec, off_t *off) {
  ssize_t total_bytes = 0;
  Status<size_t> ret;
  for (auto &v : vec) {
    ret = Write(
        writable_span(reinterpret_cast<const char *>(v.iov_base), v.iov_len),
        off);
    if (!ret) break;
    total_bytes += *ret;
  }
  if (total_bytes) return total_bytes;
  return ret;
}

ssize_t usys_writev(int fd, const iovec *iov, int iovcnt) {
  if (iovcnt <= 0) return -EINVAL;
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeRead)) return -EBADF;
  Status<size_t> ret =
      f->Writev({iov, static_cast<size_t>(iovcnt)}, &f->get_off_ref());
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_pwritev(int fd, const iovec *iov, int iovcnt, off_t offset) {
  if (iovcnt <= 0) return -EINVAL;
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeRead)) return -EBADF;
  Status<size_t> ret = f->Writev({iov, static_cast<size_t>(iovcnt)}, &offset);
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_pwritev2(int fd, const iovec *iov, int iovcnt, off_t offset,
                      int flags) {
  // TODO(jf): fix flags
  if (flags) LOG_ONCE(WARN) << "pwritev2 flags ignored " << flags;
  if (iovcnt <= 0) return -EINVAL;
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeRead)) return -EBADF;
  Status<size_t> ret = f->Writev({iov, static_cast<size_t>(iovcnt)}, &offset);
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_pwrite64(int fd, const char *buf, size_t len, off_t offset) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeRead)) return -EBADF;
  Status<size_t> ret = f->Write(writable_span(buf, len), &offset);
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

// TODO(girfan): Inefficient; extra copy can be removed?
ssize_t usys_sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
  FileTable &ftbl = myproc().get_file_table();
  File *fout = ftbl.Get(out_fd);
  if (unlikely(!fout || fout->get_mode() == kModeRead)) return -EBADF;
  File *fin = ftbl.Get(in_fd);
  if (unlikely(!fin || fin->get_mode() == kModeWrite ||
               fin->get_type() == FileType::kSocket))
    return -EBADF;
  std::vector<std::byte> buf(count);
  off_t &off = offset ? *offset : fin->get_off_ref();
  Status<size_t> ret = fin->Read(buf, &off);
  if (!ret) return MakeCError(ret);
  ret = fout->Write(buf, &fout->get_off_ref());
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

off_t usys_lseek(int fd, off_t offset, int whence) {
  // TODO(amb): validate whence
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  Status<off_t> ret = f->Seek(offset, static_cast<SeekFrom>(whence));
  if (!ret) return MakeCError(ret);
  f->get_off_ref() = *ret;
  return static_cast<off_t>(*ret);
}

int usys_fsync(int fd) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  Status<void> ret = f->Sync();
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_dup(int oldfd) {
  FileTable &ftbl = myproc().get_file_table();
  std::shared_ptr<File> f = ftbl.Dup(oldfd);
  if (!f) return -EBADF;
  return ftbl.Insert(std::move(f));
}

int usys_dup2(int oldfd, int newfd) {
  FileTable &ftbl = myproc().get_file_table();
  std::shared_ptr<File> f = ftbl.Dup(oldfd);
  if (!f) return -EBADF;
  ftbl.InsertAt(newfd, std::move(f));
  return newfd;
}

long usys_close(int fd) {
  FileTable &ftbl = myproc().get_file_table();
  if (!ftbl.Remove(fd)) return -EBADF;
  return 0;
}

long usys_newfstatat(int dirfd, const char *pathname, struct stat *statbuf,
                     int flags) {
  if (unlikely(!pathname)) return -EINVAL;
  if (flags & AT_EMPTY_PATH) {
    FileTable &ftbl = myproc().get_file_table();
    File *f = ftbl.Get(dirfd);
    if (unlikely(!f)) return -EBADF;
    Status<void> ret = f->Stat(statbuf, flags);
    if (!ret) return MakeCError(ret);
    return 0;
  } else {
    FileSystem *fs = get_fs();
    Status<void> ret = fs->Stat(pathname, statbuf);
    if (!ret) return MakeCError(ret);
    return 0;
  }
}

long usys_statfs(const char *path, struct statfs *buf) {
  FileSystem *fs = get_fs();
  Status<void> ret = fs->StatFS(path, buf);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_stat(const char *path, struct stat *statbuf) {
  FileSystem *fs = get_fs();
  Status<void> ret = fs->Stat(path, statbuf);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_getdents(unsigned int fd, void *dirp, unsigned int count) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  Status<int> ret = f->GetDents(dirp, count);
  if (!ret) return MakeCError(ret);
  return static_cast<long>(*ret);
}

long usys_getdents64(unsigned int fd, void *dirp, unsigned int count) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  Status<int> ret = f->GetDents64(dirp, count);
  if (!ret) return MakeCError(ret);
  return static_cast<long>(*ret);
}

long usys_fcntl(int fd, unsigned int cmd, unsigned long arg) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;

  switch (cmd) {
    case F_DUPFD_CLOEXEC:
      LOG_ONCE(WARN) << "fcntl ignoring cloexec";
      /* fallthrough */
    case F_DUPFD: {
      std::shared_ptr<File> fdup;
      fdup = ftbl.Dup(fd);
      if (!fdup) return -EBADF;
      return ftbl.Insert(std::move(fdup), arg);
    }
    case F_GETFD:
      if (f->get_flags() & kFlagCloseExec) {
        return FD_CLOEXEC;
      }
      return 0;
    case F_SETFD:
      if (arg != FD_CLOEXEC) {
        return -EINVAL;
      }
      f->set_flags(f->get_flags() | kFlagCloseExec);
      return 0;
    case F_GETFL:
      return f->get_mode() | f->get_flags();
    case F_SETFL:
      arg &= ~(O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_NOCTTY |
               O_TRUNC);
      if (arg & ~kFlagNonblock)
        LOG_ONCE(WARN) << "fcntl: F_SETFL ignoring some flags " << arg;
      f->set_flags((f->get_flags() & ~kFlagNonblock) | (arg & kFlagNonblock));
      return 0;
    default:
      LOG_ONCE(WARN) << "Unsupported fcntl cmd " << cmd;
      return -EINVAL;
  }
}

long usys_mkdir(const char *pathname, mode_t mode) {
  FileSystem *fs = get_fs();
  Status<void> ret = fs->CreateDirectory(pathname, mode);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_mkdirat(int fd, const char *pathname, mode_t mode) {
  if (unlikely(fd != AT_FDCWD)) return -EINVAL;
  return usys_mkdir(pathname, mode);
}

long usys_rmdir(const char *pathname) {
  FileSystem *fs = get_fs();
  Status<void> ret = fs->RemoveDirectory(pathname);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_link(const char *oldpath, const char *newpath) {
  FileSystem *fs = get_fs();
  Status<void> ret = fs->Link(oldpath, newpath);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_unlink(const char *pathname) {
  FileSystem *fs = get_fs();
  Status<void> ret = fs->Unlink(pathname);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_chown(const char *pathname, uid_t owner, gid_t group) {
  LOG(WARN) << "chown: no-op";
  return 0;
}

long usys_chmod(const char *pathname, mode_t mode) {
  LOG(WARN) << "chmod: no-op";
  return 0;
}

long usys_getcwd(char *buf, size_t size) {
  // TODO(amb): Remove this once the filesystem is more there
  return ksys_default(reinterpret_cast<unsigned long>(buf), size, 0, 0, 0, 0,
                      __NR_getcwd);
}

#if 0
long usys_chdir(const char *path) {
  // TODO(girfan): Remove this once the filesystem is more there
  return ksys_default(reinterpret_cast<unsigned long>(path), 0, 0, 0, 0, 0,
                      __NR_chdir);
}
#endif

long usys_ioctl(int fd, unsigned long request, char *argp) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  auto ret = f->Ioctl(request, argp);
  if (!ret) return MakeCError(ret);
  return 0;
}

mode_t usys_umask(mode_t mask) {
  FileSystem *fs = get_fs();
  mode_t old = fs->get_umask();
  fs->set_umask(mask);
  return old;
}

}  // namespace junction
