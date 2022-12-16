extern "C" {
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
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

int FileTable::Insert(std::shared_ptr<File> f) {
  rt::SpinGuard g(lock_);

  // Find the first empty slot to insert the file.
  size_t i;
  for (i = 0; i < farr_->len; ++i) {
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
  rt::SpinGuard g(lock_);

  // Check if the file is present.
  if (static_cast<size_t>(fd) >= farr_->len) return false;
  if (!farr_->files[fd]) return false;

  // Remove the file.
  farr_->files[fd].reset();
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
  const std::string_view path(pathname);
  FileSystem *fs = get_fs();
  Status<std::shared_ptr<File>> f = fs->Open(path, mode, flags);
  if (unlikely(!f)) return -ENOENT;
  FileTable &ftbl = myproc().get_file_table();
  return ftbl.Insert(std::move(*f));
}

void *usys_mmap(void *addr, size_t length, int prot, int flags, int fd,
                off_t offset) {
  if (fd < 0) {
    intptr_t ret = ksys_mmap(addr, length, prot, flags, fd, offset);
    if (ret < 0) return MAP_FAILED;
    return reinterpret_cast<void *>(ret);
  }
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return MAP_FAILED;
  Status<void *> ret = f->MMap(addr, length, prot, flags, offset);
  if (!ret) return MAP_FAILED;
  return static_cast<void *>(*ret);
}

int usys_munmap(void *addr, size_t length) {
  if (unlikely(addr == nullptr)) return -EINVAL;
  // TODO(girfan): Track the addresses when they were mmaped; this is just a bad
  // hack.
  return ksys_munmap(addr, length);
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

ssize_t usys_pwrite64(int fd, const char *buf, size_t len, off_t offset) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeRead)) return -EBADF;
  Status<size_t> ret = f->Write(writable_span(buf, len), &offset);
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
  if (flags & AT_EMPTY_PATH) {
    FileTable &ftbl = myproc().get_file_table();
    File *f = ftbl.Get(dirfd);
    if (unlikely(!f)) return -EBADF;
    Status<int> ret = f->Stat(statbuf, flags);
    if (!ret) return MakeCError(ret);
    return static_cast<long>(*ret);
  } else {
    // TODO(girfan): Eventually we should not allow this. Only files from the
    // filesystem should be able to do this. We can fstat when we open
    // files/mock it for newly created files.
    return static_cast<long>(ksys_newfstatat(dirfd, pathname, statbuf, flags));
  }
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

}  // namespace junction
