#include "junction/kernel/file.h"

#include <algorithm>
#include <bit>
#include <memory>

#include "junction/base/io.h"
#include "junction/kernel/proc.h"

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
    : farr_(std::make_unique<FArr>(kInitialCap)), rcup_(farr_.get()) {}

FileTable::~FileTable() = default;

void FileTable::Resize(size_t len) {
  assert(lock_.IsHeld());
  size_t new_cap = std::bit_ceil(len) * kOversizeRatio;
  if (farr_->cap != new_cap) {
    auto narr = detail::CopyFileArray(*farr_, new_cap);
    narr->len = len;
    rcup_.set(narr.get());
    rt::RCUFree(std::move(farr_));
    farr_ = std::move(narr);
  }
}

std::shared_ptr<File> FileTable::Dup(int fd) {
  rt::RCURead l;
  rt::RCUReadGuard g(&l);
  const FArr *tbl = rcup_.get();
  if (unlikely(static_cast<size_t>(fd) >= tbl->len)) return {};
  return tbl->files[fd];
}

int FileTable::Insert(std::shared_ptr<File> f) {
  rt::SpinGuard g(&lock_);

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
  farr_->files[i] = std::move(f);
  return static_cast<int>(i);
}

void FileTable::InsertAt(int fd, std::shared_ptr<File> f) {
  rt::SpinGuard g(&lock_);
  if (static_cast<size_t>(fd) >= farr_->len) Resize(fd);
  farr_->files[fd] = std::move(f);
}

bool FileTable::Remove(int fd) {
  rt::SpinGuard g(&lock_);

  // Check if the file is present.
  if (!farr_->files[fd]) return false;

  // Remove the file.
  farr_->files[fd].reset();
  if (static_cast<size_t>(fd) != farr_->len - 1) return true;

  // Try to shrink the table.
  size_t i;
  for (i = farr_->len - 2; i > 0; --i) {
    if (farr_->files[i]) break;
  }
  Resize(i + 1);
  return true;
}

//
// System call implementations
//

ssize_t usys_read(int fd, char *buf, size_t len) {
  FileTable &ftbl = myproc()->ftable;
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeWrite)) return -EBADF;
  Status<size_t> ret = f->Read(readable_span(buf, len), &f->get_off_ref());
  if (!ret) return -ret.error().code();
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_write(int fd, const char *buf, size_t len) {
  FileTable &ftbl = myproc()->ftable;
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeRead)) return -EBADF;
  Status<size_t> ret = f->Write(writable_span(buf, len), &f->get_off_ref());
  if (!ret) return -ret.error().code();
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_pread(int fd, char *buf, size_t len, off_t offset) {
  FileTable &ftbl = myproc()->ftable;
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeWrite)) return -EBADF;
  Status<size_t> ret = f->Read(readable_span(buf, len), &offset);
  if (!ret) return -ret.error().code();
  return static_cast<ssize_t>(*ret);
}

ssize_t usys_pwrite(int fd, const char *buf, size_t len, off_t offset) {
  FileTable &ftbl = myproc()->ftable;
  File *f = ftbl.Get(fd);
  if (unlikely(!f || f->get_mode() == kModeRead)) return -EBADF;
  Status<size_t> ret = f->Write(writable_span(buf, len), &offset);
  if (!ret) return -ret.error().code();
  return static_cast<ssize_t>(*ret);
}

off_t usys_lseek(int fd, off_t offset, int whence) {
  // TODO(amb): validate whence
  FileTable &ftbl = myproc()->ftable;
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  Status<off_t> ret = f->Seek(offset, static_cast<SeekFrom>(whence));
  if (!ret) return -ret.error().code();
  f->get_off_ref() = *ret;
  return static_cast<off_t>(*ret);
}

int usys_fsync(int fd) {
  FileTable &ftbl = myproc()->ftable;
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  Status<void> ret = f->Sync();
  if (!ret) return -ret.error().code();
  return 0;
}

int usys_dup(int oldfd) {
  FileTable &ftbl = myproc()->ftable;
  std::shared_ptr<File> f = ftbl.Dup(oldfd);
  if (!f) return -EBADF;
  return ftbl.Insert(std::move(f));
}

int usys_dup2(int oldfd, int newfd) {
  FileTable &ftbl = myproc()->ftable;
  std::shared_ptr<File> f = ftbl.Dup(oldfd);
  if (!f) return -EBADF;
  ftbl.InsertAt(newfd, std::move(f));
  return newfd;
}

int usys_close(int fd) {
  FileTable &ftbl = myproc()->ftable;
  if (!ftbl.Remove(fd)) return -EBADF;
  return 0;
}

}  // namespace junction
