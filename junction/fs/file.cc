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
#include "junction/fs/file.h"
#include "junction/fs/fs.h"
#include "junction/junction.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace {

constexpr size_t kInitialCap = 64;
constexpr size_t kOversizeRatio = 2;

}  // namespace

namespace junction {

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

FileTable::FileTable()
    : farr_(std::make_unique<FArr>(kInitialCap)),
      rcup_(farr_.get()),
      close_on_exec_(kInitialCap) {}

FileTable::FileTable(const FileTable &o)
    : farr_(CopyFileArray(*o.farr_, o.farr_->len)),
      rcup_(farr_.get()),
      close_on_exec_(o.close_on_exec_) {}

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

int FileTable::Insert(std::shared_ptr<File> f, bool cloexec, size_t lowest) {
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
  bool invalidate;
  {
    rt::SpinGuard g(lock_);
    if (static_cast<size_t>(fd) >= farr_->len) Resize(fd + 1);
    invalidate = !!farr_->files[fd];
    farr_->files[fd] = std::move(f);
    if (cloexec) close_on_exec_.set(fd);
  }
  if (invalidate) myproc().get_procfs().NotifyFDDestroy(fd);
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
  myproc().get_procfs().NotifyFDDestroy(fd);
  return true;
}

void FileTable::RemoveRange(size_t low, size_t high) {
  std::vector<std::shared_ptr<File>> tmp;
  std::vector<int> tmp_fd;
  {
    rt::SpinGuard g(lock_);
    high = std::min(high, farr_->len - 1);
    tmp.reserve(high - low + 1);
    for (size_t fd = low; fd <= high; fd++) {
      if (!farr_->files[fd]) continue;
      tmp.emplace_back(std::move(farr_->files[fd]));
      close_on_exec_.clear(fd);
      tmp_fd.push_back(fd);
    }
  }
  auto &procfs = myproc().get_procfs();
  for (auto &fd : tmp_fd) procfs.NotifyFDDestroy(fd);
}

void FileTable::SetCloseOnExecRange(size_t low, size_t high) {
  rt::SpinGuard g(lock_);

  high = std::min(high, farr_->len - 1);
  for (size_t fd = low; fd <= high; fd++)
    if (farr_->files[fd]) close_on_exec_.set(fd);
}

void FileTable::SetCloseOnExec(int fd) {
  rt::SpinGuard g(lock_);
  assert(static_cast<size_t>(fd) < farr_->len && farr_->files[fd]);
  close_on_exec_.set(fd);
}

bool FileTable::TestCloseOnExec(int fd) {
  rt::SpinGuard g(lock_);
  assert(static_cast<size_t>(fd) < farr_->len && farr_->files[fd]);
  return close_on_exec_.test(fd);
}

void FileTable::ClearCloseOnExec(int fd) {
  rt::SpinGuard g(lock_);
  assert(static_cast<size_t>(fd) < farr_->len && farr_->files[fd]);
  return close_on_exec_.clear(fd);
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

long usys_ftruncate(int fd, off_t length) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (!f) return -EBADF;
  auto ret = f->Truncate(length);
  if (!ret) return MakeCError(ret);
  return 0;
}

ssize_t usys_read(int fd, char *buf, size_t len) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || !f->is_readable())) return -EBADF;
  Status<size_t> ret = f->Read(readable_span(buf, len), &f->get_off_ref());
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_readv(int fd, struct iovec *iov, int iovcnt) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || !f->is_readable())) return -EBADF;
  Status<size_t> ret =
      f->Readv({iov, static_cast<size_t>(iovcnt)}, &f->get_off_ref());
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_write(int fd, const char *buf, size_t len) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || !f->is_writeable())) return -EBADF;
  Status<size_t> ret = f->Write(writable_span(buf, len), &f->get_off_ref());
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_pread64(int fd, char *buf, size_t len, off_t offset) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || !f->is_readable())) return -EBADF;
  Status<size_t> ret = f->Read(readable_span(buf, len), &offset);
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

Status<void> File::Truncate(off_t newlen) {
  if (ino_) return ino_->SetSize(static_cast<size_t>(newlen));
  return MakeError(EINVAL);
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

Status<void> File::Stat(struct stat *statbuf) const {
  assert(ino_);
  Status<void> ret = ino_->GetStats(statbuf);
  if (!ret) return MakeError(ret);
  return {};
}

Status<void> File::StatFS(struct statfs *buf) const {
  if (!ino_) return MakeError(ENOSYS);
  Status<void> stat = ino_->GetStatFS(buf);
  if (!stat) return MakeError(stat);
  return {};
}

Status<long> File::Ioctl(unsigned long request, char *argp) {
  switch (request) {
    case TCGETS:
    case TIOCGPGRP:
      return MakeError(ENOTTY);
  }

  if (request == FIONBIO) {
    int nonblock = *reinterpret_cast<int *>(argp);
    if (nonblock)
      set_flag(kFlagNonblock);
    else
      clear_flag(kFlagNonblock);
    return 0;
  }

  return MakeError(EINVAL);
}

void File::save_dent_path(cereal::BinaryOutputArchive &ar) const {
  Status<std::string> ret = get_dent_ref().GetPathStr();
  if (!ret) throw std::runtime_error("stale file handle");
  ar(*ret);
}

std::shared_ptr<DirectoryEntry> File::restore_dent_path(
    cereal::BinaryInputArchive &ar) {
  std::string path;
  ar(path);
  Status<std::shared_ptr<DirectoryEntry>> ret =
      LookupDirEntry(FSRoot::GetGlobalRoot(), path);
  if (unlikely(!ret))
    throw std::runtime_error("failed to find file on restore at path " + path);
  return std::move(*ret);
}

struct linux_dirent64 {
  ino64_t d_ino;           /* 64-bit inode number */
  off64_t d_off;           /* 64-bit offset to next structure */
  unsigned short d_reclen; /* Size of this dirent */
  unsigned char d_type;    /* File type */
  char d_name[];           /* Filename (null-terminated) */
};

struct linux_dirent {
  unsigned long d_ino;     /* inode number */
  unsigned long d_off;     /* offset to next structure */
  unsigned short d_reclen; /* Size of this dirent */
  char d_name[1];          /* Filename (null-terminated) plus 1 byte d_type */
};

size_t DirentToDent64(dir_entry &ent, std::span<std::byte> dirp, off_t off) {
  size_t ent_size = sizeof(linux_dirent64) + ent.name.size() + 1;
  ent_size = AlignUp(ent_size, alignof(linux_dirent64));
  if (ent_size > dirp.size()) return 0;
  linux_dirent64 &dent = *reinterpret_cast<linux_dirent64 *>(dirp.data());
  dent.d_ino = ent.inum;
  dent.d_reclen = ent_size;
  dent.d_off = off;
  dent.d_type = ent.type >> kTypeShift;
  std::memcpy(dent.d_name, ent.name.data(), ent.name.size());
  dent.d_name[ent.name.size()] = '\0';
  return ent_size;
}

size_t DirentToDent(dir_entry &ent, std::span<std::byte> dirp, off_t off) {
  size_t ent_size = sizeof(linux_dirent) + ent.name.size() + 1;
  ent_size = AlignUp(ent_size, alignof(linux_dirent));
  if (ent_size > dirp.size()) return 0;
  linux_dirent &dent = *reinterpret_cast<linux_dirent *>(dirp.data());
  dent.d_ino = ent.inum;
  dent.d_reclen = ent_size;
  dent.d_off = off;
  std::memcpy(dent.d_name, ent.name.data(), ent.name.size());
  dent.d_name[ent.name.size()] = '\0';
  dirp[ent_size - 1] = static_cast<std::byte>(ent.type >> kTypeShift);
  return ent_size;
}

template <typename ConvertFn>
Status<long> DoDirent(IDir &dir, std::span<std::byte> dirp, off_t &off,
                      ConvertFn func) {
  std::vector<dir_entry> ents = dir.GetDents();
  std::span<std::byte> out = dirp;
  while (static_cast<size_t>(off) < ents.size()) {
    size_t sz = func(ents[off], out, off);
    if (!sz) {
      if (out.size() == dirp.size()) return MakeError(EINVAL);
      break;
    }
    out = out.subspan(sz);
    off++;
  }
  return dirp.size() - out.size();
}

File::File(FileType type, unsigned int flags, FileMode mode,
           std::shared_ptr<DirectoryEntry> ent)
    : type_(type),
      flags_(flags),
      mode_(mode),
      ino_(&ent->get_inode_ref()),
      dent_(std::move(ent)) {}

[[nodiscard]] std::string File::get_filename() const {
  if (!dent_) return "";
  std::string out;
  out.reserve(PATH_MAX);
  std::ostringstream ss(std::move(out));
  Status<void> ret = dent_->GetFullPath(ss);
  if (unlikely(!ret)) return "[STALE]";
  return ss.str();
}

DirectoryFile::DirectoryFile(unsigned int flags, FileMode mode,
                             std::shared_ptr<DirectoryEntry> dent)
    : File(FileType::kDirectory, flags, mode, std::move(dent)) {}

Status<long> DirectoryFile::GetDents(std::span<std::byte> dirp, off_t *off) {
  IDir &dir = static_cast<IDir &>(get_inode_ref());
  return DoDirent(dir, dirp, *off, DirentToDent);
}

Status<long> DirectoryFile::GetDents64(std::span<std::byte> dirp, off_t *off) {
  IDir &dir = static_cast<IDir &>(get_inode_ref());
  return DoDirent(dir, dirp, *off, DirentToDent64);
}

SoftLinkFile::SoftLinkFile(unsigned int flags, FileMode mode,
                           std::shared_ptr<DirectoryEntry> dent)
    : File(FileType::kSymlink, flags, mode, std::move(dent)) {
  assert(dent->get_inode_ref().is_symlink());
}

Status<long> SoftLinkFile::ReadLink(std::span<std::byte> buf) {
  ISoftLink &ino = static_cast<ISoftLink &>(get_inode_ref());
  std::string lpath = ino.ReadLink();
  size_t copy = std::min(buf.size(), lpath.size());
  std::memcpy(buf.data(), lpath.data(), copy);
  return copy;
}

ssize_t usys_writev(int fd, const iovec *iov, int iovcnt) {
  if (iovcnt <= 0) return -EINVAL;
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || !f->is_writeable())) return -EBADF;
  Status<size_t> ret =
      f->Writev({iov, static_cast<size_t>(iovcnt)}, &f->get_off_ref());
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_pwritev(int fd, const iovec *iov, int iovcnt, off_t offset) {
  if (iovcnt <= 0) return -EINVAL;
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || !f->is_writeable())) return -EBADF;
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
  if (unlikely(!f || !f->is_writeable())) return -EBADF;
  Status<size_t> ret = f->Writev({iov, static_cast<size_t>(iovcnt)}, &offset);
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_pwrite64(int fd, const char *buf, size_t len, off_t offset) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || !f->is_writeable())) return -EBADF;
  Status<size_t> ret = f->Write(writable_span(buf, len), &offset);
  if (!ret) return MakeCError(ret);
  return static_cast<ssize_t>(*ret);
}

// TODO(girfan): Inefficient; extra copy can be removed?
ssize_t usys_sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
  FileTable &ftbl = myproc().get_file_table();
  File *fout = ftbl.Get(out_fd);
  if (unlikely(!fout || !fout->is_writeable())) return -EBADF;
  File *fin = ftbl.Get(in_fd);
  if (unlikely(!fin || !fin->is_readable() ||
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

long usys_fsync(int fd) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  Status<void> ret = f->Sync();
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_fdatasync(int fd) { return usys_fsync(fd); }

long usys_dup(int oldfd) {
  FileTable &ftbl = myproc().get_file_table();
  std::shared_ptr<File> f = ftbl.Dup(oldfd);
  if (!f) return -EBADF;
  return ftbl.Insert(std::move(f));
}

long usys_dup2(int oldfd, int newfd) {
  if (oldfd == newfd) return newfd;
  FileTable &ftbl = myproc().get_file_table();
  std::shared_ptr<File> f = ftbl.Dup(oldfd);
  if (!f) return -EBADF;
  ftbl.InsertAt(newfd, std::move(f));
  return newfd;
}

long usys_dup3(int oldfd, int newfd, int flags) {
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

long usys_fstat(int fd, struct stat *statbuf) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  Status<void> ret = f->Stat(statbuf);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_newfstatat(int dirfd, const char *c_path, struct stat *statbuf,
                     int flags) {
  // Needed for compatibility with fish-shell.
  if (unlikely(!c_path)) return -EFAULT;

  const std::string_view path(c_path);
  std::shared_ptr<Inode> inode;

  if ((flags & kAtEmptyPath) && path.size() == 0) {
    if (dirfd != kAtFdCwd) return usys_fstat(dirfd, statbuf);
    inode = myproc().get_fs().get_cwd();
  } else {
    bool chase_link = !(flags & kAtNoFollowLink);
    Status<std::shared_ptr<Inode>> tmp =
        LookupInode(myproc(), dirfd, path, chase_link);
    if (!tmp) return MakeCError(tmp);
    inode = std::move(*tmp);
  }

  Status<void> stat = inode->GetStats(statbuf);
  if (!stat) return MakeCError(stat);
  return 0;
}

long usys_getdents(unsigned int fd, void *dirp, unsigned int count) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  Status<long> ret = f->GetDents({reinterpret_cast<std::byte *>(dirp), count},
                                 &f->get_off_ref());
  if (!ret) return MakeCError(ret);
  return *ret;
}

long usys_getdents64(unsigned int fd, void *dirp, unsigned int count) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  Status<long> ret = f->GetDents64({reinterpret_cast<std::byte *>(dirp), count},
                                   &f->get_off_ref());
  if (!ret) return MakeCError(ret);
  return *ret;
}

long usys_fstatfs(int fd, struct statfs *buf) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  Status<void> stat = f->StatFS(buf);
  if (!stat) return MakeCError(stat);
  return 0;
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
      return ftbl.Insert(std::move(fdup), cmd == F_DUPFD_CLOEXEC, arg);
    }
    case F_GETFD:
      return ftbl.TestCloseOnExec(fd) ? FD_CLOEXEC : 0;
    case F_SETFD:
      if (arg == FD_CLOEXEC)
        ftbl.SetCloseOnExec(fd);
      else if (arg == 0)
        ftbl.ClearCloseOnExec(fd);
      else
        return -EINVAL;
      return 0;
    case F_GETFL:
      return ToFlags(f->get_mode()) | f->get_flags();
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

long usys_close_range(int first, int last, unsigned int flags) {
  if (unlikely(flags & ~CLOSE_RANGE_CLOEXEC)) return -EINVAL;
  FileTable &ftbl = myproc().get_file_table();
  if (flags & CLOSE_RANGE_CLOEXEC)
    ftbl.SetCloseOnExecRange(first, last);
  else
    ftbl.RemoveRange(first, last);
  return 0;
}

bool DoFileTableIoctls(FileTable &ftbl, int fd, unsigned long request) {
  if (request == FIOCLEX)
    ftbl.SetCloseOnExec(fd);
  else if (request == FIONCLEX)
    ftbl.ClearCloseOnExec(fd);
  else
    return false;
  return true;
}

long usys_ioctl(int fd, unsigned int request, char *argp) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  if (DoFileTableIoctls(ftbl, fd, request)) return 0;
  auto ret = f->Ioctl(request, argp);
  if (!ret) return MakeCError(ret);
  return *ret;
}

long usys_umask(mode_t mask) { return myproc().get_fs().SetUmask(mask); }

}  // namespace junction
