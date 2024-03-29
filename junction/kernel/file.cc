extern "C" {
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
}

#include <algorithm>
#include <bit>
#include <cstring>
#include <memory>

#include "junction/base/finally.h"
#include "junction/base/io.h"
#include "junction/bindings/log.h"
#include "junction/junction.h"
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

std::unique_ptr<FileSystem> fs_;

namespace detail {

file_array::file_array(size_t cap) : cap(cap) {
  if (unlikely(cap > ArrayMaxElements<std::shared_ptr<File>>()))
    throw std::bad_alloc();
  files.reset(new std::shared_ptr<File>[cap]());
}
file_array::~file_array() = default;

std::unique_ptr<file_array> CopyFileArray(const file_array &src, size_t cap) {
  auto dst = std::make_unique<file_array>(cap);
  assert(src.len <= cap);
  std::copy_n(src.files.get(), src.len, dst->files.get());
  dst->len = src.len;
  return dst;
}

}  // namespace detail

inline std::string_view PrependCwd(const char *pathname,
                                   std::span<std::byte> dst) {
  // Don't prepend if previous pathname was absoulte.
  if (pathname[0] == '/') return pathname;

  // Fill dst with this proc's cwd, leaving 1 byte for a null terminator.
  size_t bytes = myproc().GetCwd(dst.first(dst.size() - 1));
  size_t tocopy = std::min(strlen(pathname), dst.size() - 1 - bytes);
  std::memcpy(dst.data() + bytes, pathname, tocopy);
  dst[bytes + tocopy] = std::byte{'\0'};
  return {reinterpret_cast<char *>(dst.data()), bytes + tocopy};
}

FileTable::FileTable()
    : farr_(std::make_unique<FArr>(kInitialCap)),
      rcup_(farr_.get()),
      close_on_exec_(kInitialCap) {}

FileTable::~FileTable() = default;

FileTable::FileTable(const FileTable &o)
    : farr_(CopyFileArray(*o.farr_, o.farr_->len)),
      rcup_(farr_.get()),
      close_on_exec_(o.close_on_exec_) {}

FileTable &FileTable::operator=(const FileTable &o) {
  farr_ = CopyFileArray(*o.farr_, o.farr_->len);
  rcup_.set(farr_.get());
  close_on_exec_ = o.close_on_exec_;
  return *this;
}

void FileTable::Resize(size_t len) {
  assert(lock_.IsHeld());
  size_t new_cap = std::bit_ceil(len) * kOversizeRatio;
  if (farr_->cap < new_cap) {
    auto narr = detail::CopyFileArray(*farr_, new_cap);
    narr->len = len;
    rcup_.set(narr.get());
    rt::RCUFree(std::move(farr_));
    farr_ = std::move(narr);
    close_on_exec_.resize(new_cap);
  }
}

std::shared_ptr<File> FileTable::Dup(int fd) {
  rt::RCURead l;
  rt::RCUReadGuard g(l);
  const FArr *tbl = rcup_.get();
  if (unlikely(static_cast<size_t>(fd) >= tbl->len)) return {};
  return tbl->files[fd];
}

int FileTable::Insert(std::shared_ptr<File> f, size_t lowest, bool cloexec) {
  rt::SpinGuard g(lock_);
  size_t i;
  auto fin = finally([this, cloexec, &i] {
    if (cloexec) close_on_exec_.set(i);
  });

  // Find the first empty slot to insert the file.
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

void FileTable::InsertAt(int fd, std::shared_ptr<File> f, bool cloexec) {
  rt::SpinGuard g(lock_);
  if (static_cast<size_t>(fd) >= farr_->len) Resize(fd);
  farr_->files[fd] = std::move(f);
  if (cloexec) close_on_exec_.set(fd);
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

    // Clear close-on-exec.
    close_on_exec_.clear(fd);
  }
  return true;
}

void FileTable::RemoveRange(int low, int high) {
  assert(low >= 0 && high >= 0);
  std::vector<std::shared_ptr<File>> tmp;
  {
    rt::SpinGuard g(lock_);
    int max = farr_->len - 1;
    low = std::min(low, max);
    high = std::min(high, max);

    tmp.reserve(high - low + 1);
    for (int fd = low; fd <= high; fd++) {
      if (!farr_->files[fd]) continue;
      tmp.emplace_back(std::move(farr_->files[fd]));
      close_on_exec_.clear(fd);
    }
  }
}

void FileTable::SetCloseOnExecRange(int low, int high) {
  assert(low >= 0 && high >= 0);
  rt::SpinGuard g(lock_);

  int max = farr_->len;
  low = std::min(low, max);
  high = std::min(high, max);

  for (int fd = low; fd <= high; fd++) {
    if (farr_->files[fd]) close_on_exec_.set(fd);
  }
}

void FileTable::SetCloseOnExec(int fd) {
  rt::SpinGuard g(lock_);
  assert(fd >= 0 && static_cast<size_t>(fd) < farr_->len && farr_->files[fd]);
  close_on_exec_.set(fd);
}

bool FileTable::TestCloseOnExec(int fd) {
  rt::SpinGuard g(lock_);
  assert(fd >= 0 && static_cast<size_t>(fd) < farr_->len && farr_->files[fd]);
  return close_on_exec_.test(fd);
}

void FileTable::DoCloseOnExec() {
  rt::SpinGuard g(lock_);
  for_each_set_bit(close_on_exec_,
                   [this](size_t i) { farr_->files[i].reset(); });
  close_on_exec_.clear();
}

//
// System call implementations
//

void init_fs(FileSystem *fs) {
  // Set the filesystem.
  fs_.reset(fs);
}

long usys_open(const char *pathname, int flags, mode_t mode) {
  FileSystem *fs = get_fs();

  std::byte real_path[PATH_MAX + 1];
  std::string_view path = PrependCwd(pathname, real_path);

  Status<std::shared_ptr<File>> f = fs->Open(path, mode, flags);
  if (unlikely(!f)) return -ENOENT;
  FileTable &ftbl = myproc().get_file_table();
  return ftbl.Insert(std::move(*f), (flags & kFlagCloseExec) > 0);
}

long usys_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
  if (unlikely(dirfd != AT_FDCWD)) return -EINVAL;
  return usys_open(pathname, flags, mode);
}

long usys_ftruncate(int fd, off_t length) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (!f) return -EBADF;
  auto ret = f->Truncate(length);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_fallocate(int fd, int mode, off_t offset, off_t len) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (!f) return -EBADF;
  auto ret = f->Allocate(mode, offset, len);
  if (!ret) return MakeCError(ret);
  return 0;
}

ssize_t usys_read(int fd, char *buf, size_t len) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeWrite)) return -EBADF;
  Status<size_t> ret = f->Read(readable_span(buf, len), &f->get_off_ref());
  if (!ret && ret.error() == EINTR) return -ERESTARTSYS;
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_readv(int fd, struct iovec *iov, int iovcnt) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeWrite)) return -EBADF;
  Status<size_t> ret =
      f->Readv({iov, static_cast<size_t>(iovcnt)}, &f->get_off_ref());
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
    if (!v.iov_len) continue;
    ret = Write(
        writable_span(reinterpret_cast<const char *>(v.iov_base), v.iov_len),
        off);
    if (!ret) break;
    total_bytes += *ret;
    if (*ret < v.iov_len) break;
  }
  if (total_bytes) return total_bytes;
  return ret;
}

Status<size_t> File::Readv(std::span<iovec> vec, off_t *off) {
  ssize_t total_bytes = 0;
  Status<size_t> ret;
  for (auto &v : vec) {
    if (!v.iov_len) continue;
    ret = Read(readable_span(reinterpret_cast<char *>(v.iov_base), v.iov_len),
               off);
    if (!ret) break;
    total_bytes += *ret;
    if (!is_nonblocking() || *ret < v.iov_len) break;
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
  if (oldfd == newfd) return newfd;
  FileTable &ftbl = myproc().get_file_table();
  std::shared_ptr<File> f = ftbl.Dup(oldfd);
  if (!f) return -EBADF;
  ftbl.InsertAt(newfd, std::move(f));
  return newfd;
}

int usys_dup3(int oldfd, int newfd, int flags) {
  if (oldfd == newfd) return -EINVAL;
  FileTable &ftbl = myproc().get_file_table();
  std::shared_ptr<File> f = ftbl.Dup(oldfd);
  if (!f) return -EBADF;
  ftbl.InsertAt(newfd, std::move(f), (flags & kFlagCloseExec) > 0);
  return newfd;
}

long usys_close(int fd) {
  FileTable &ftbl = myproc().get_file_table();
  if (!ftbl.Remove(fd)) return -EBADF;
  return 0;
}

long usys_close_range(int first, int last, unsigned int flags) {
  if (unlikely(flags & ~CLOSE_RANGE_CLOEXEC)) return -EINVAL;
  FileTable &ftbl = myproc().get_file_table();
  if (flags & CLOSE_RANGE_CLOEXEC)
    ftbl.SetCloseOnExecRange(first, last);
  else
    ftbl.RemoveRange(first, last);
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
    std::byte real_path[PATH_MAX + 1];
    Status<void> ret = fs->Stat(PrependCwd(pathname, real_path), statbuf);
    if (!ret) return MakeCError(ret);
    return 0;
  }
}

long usys_statfs(const char *path, struct statfs *buf) {
  FileSystem *fs = get_fs();
  std::byte real_path[PATH_MAX + 1];
  Status<void> ret = fs->StatFS(PrependCwd(path, real_path), buf);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_stat(const char *path, struct stat *statbuf) {
  FileSystem *fs = get_fs();
  std::byte real_path[PATH_MAX + 1];
  Status<void> ret = fs->Stat(PrependCwd(path, real_path), statbuf);
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
      /* fallthrough */
    case F_DUPFD: {
      std::shared_ptr<File> fdup;
      fdup = ftbl.Dup(fd);
      if (!fdup) return -EBADF;
      return ftbl.Insert(std::move(fdup), arg, cmd == F_DUPFD_CLOEXEC);
    }
    case F_GETFD:
      return ftbl.TestCloseOnExec(fd) ? FD_CLOEXEC : 0;
    case F_SETFD:
      if (arg != FD_CLOEXEC) return -EINVAL;
      ftbl.SetCloseOnExec(fd);
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
  std::byte real_path[PATH_MAX + 1];
  Status<void> ret = fs->CreateDirectory(PrependCwd(pathname, real_path), mode);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_mkdirat(int fd, const char *pathname, mode_t mode) {
  if (unlikely(fd != AT_FDCWD)) return -EINVAL;
  return usys_mkdir(pathname, mode);
}

long usys_rmdir(const char *pathname) {
  FileSystem *fs = get_fs();
  std::byte real_path[PATH_MAX + 1];
  Status<void> ret = fs->RemoveDirectory(PrependCwd(pathname, real_path));
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_link(const char *oldpath, const char *newpath) {
  FileSystem *fs = get_fs();
  std::byte real_old[PATH_MAX + 1];
  std::byte real_new[PATH_MAX + 1];
  Status<void> ret =
      fs->Link(PrependCwd(oldpath, real_old), PrependCwd(newpath, real_new));
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_unlink(const char *pathname) {
  FileSystem *fs = get_fs();
  std::byte real_path[PATH_MAX + 1];
  Status<void> ret = fs->Unlink(PrependCwd(pathname, real_path));
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
  size_t copied = myproc().GetCwd(readable_span(buf, size));
  if (unlikely(copied >= size)) return -ERANGE;
  buf[copied] = '\0';
  return copied + 1;
}

long usys_chdir(const char *pathname) {
  size_t prefix_bytes = 0;

  std::byte real_path[PATH_MAX + 1];
  if (pathname[0] != '/') prefix_bytes = myproc().GetCwd(real_path);

  size_t slen = strlen(pathname);
  if (pathname[slen - 1] == '/') slen--;

  if (slen + prefix_bytes + 1 > PATH_MAX) return -ENAMETOOLONG;
  std::memcpy(&real_path[prefix_bytes], pathname, slen);
  real_path[prefix_bytes + slen] = std::byte{'/'};
  real_path[prefix_bytes + slen + 1] = std::byte{'\0'};
  std::string_view s(reinterpret_cast<char *>(real_path),
                     prefix_bytes + slen + 1);
  myproc().SetCwd(s);
  return 0;
}

long usys_access(const char *pathname, int mode) {
  FileSystem *fs = get_fs();
  std::byte real_path[PATH_MAX + 1];
  auto ret = fs->Access(PrependCwd(pathname, real_path), mode);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_ioctl(int fd, unsigned long request, char *argp) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  auto ret = f->Ioctl(request, argp);
  if (!ret) return MakeCError(ret);
  return 0;
}

// TODO: fix this implementation
ssize_t usys_readlinkat(int dirfd, const char *pathname, char *buf,
                        size_t bufsiz) {
  if (dirfd != AT_FDCWD) return -EINVAL;

  std::byte real_path[PATH_MAX + 1];
  std::string_view path = PrependCwd(pathname, real_path);

  if (path == "/proc/self/exe") {
    auto str = myproc().get_bin_path();
    size_t copy = std::min(bufsiz, str.size());
    std::memcpy(buf, str.data(), copy);
    return copy;
  }

  // otherwise just say this path is not a link, good enough for Java
  return -EINVAL;
}

// TODO: fix this implementation
ssize_t usys_readlink(const char *pathname, char *buf, size_t bufsiz) {
  return usys_readlinkat(AT_FDCWD, pathname, buf, bufsiz);
}

// TODO(jf): seems like this should be per-Process.
mode_t usys_umask(mode_t mask) {
  FileSystem *fs = get_fs();
  mode_t old = fs->get_umask();
  fs->set_umask(mask);
  return old;
}

}  // namespace junction
