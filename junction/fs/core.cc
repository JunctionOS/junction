// core.cc - core file system support

#include <algorithm>
#include <utility>

#include "junction/base/string.h"
#include "junction/fs/file.h"
#include "junction/fs/fs.h"

namespace junction {

namespace {

using Path = std::pair<std::shared_ptr<IDir>, std::string_view>;

constexpr bool NameIsValid(std::string_view name) {
  return std::none_of(std::cbegin(name), std::cend(name),
                      [](char c) { return c == '/' || c == '\0'; });
}

// LookupInode finds an inode from a path
Status<std::shared_ptr<Inode>> LookupInode(
    std::shared_ptr<Inode> pos, const std::vector<std::string_view> &spath) {
  for (std::string_view v : spath) {
    if (!pos->is_dir()) return MakeError(ENOTDIR);
    auto &dir = static_cast<IDir &>(*pos);
    if (v.empty() || v == ".") continue;
    if (v == "..") {
      pos = dir.get_parent();
      continue;
    }
    Status<std::shared_ptr<Inode>> ret = dir.Lookup(v);
    if (!ret) return MakeError(ret);
    pos = std::move(*ret);
  }

  return pos;
}

// LookupPath converts a path into a directory inode and an entry name
Status<Path> LookupPath(std::shared_ptr<Inode> pos, std::string_view path) {
  std::vector<std::string_view> spath = split(path, '/');
  if (spath.empty()) return MakeError(EINVAL);

  // strip off the file name
  std::string_view name = spath.back();
  spath.pop_back();
  if (!NameIsValid(name)) return MakeError(EINVAL);

  // look up the directory
  Status<std::shared_ptr<Inode>> ret = LookupInode(pos, spath);
  if (!ret) return MakeError(ret);
  if (!(*ret)->is_dir()) return MakeError(ENOTDIR);
  if ((*ret)->is_stale()) return MakeError(ESTALE);
  return Path(std::static_pointer_cast<IDir>(std::move(*ret)), name);
}

// Lookup finds a directory inode and entry name starting from the root or cwd
Status<Path> Lookup(std::string_view path) {
  FSRoot &fs = myproc().get_filesystem();
  std::shared_ptr<IDir> dir = path[0] == '/' ? fs.get_root() : fs.get_cwd();
  return LookupPath(dir, path);
}

// LookupAt finds a directory inode and entry name starting from a directory FD
Status<Path> LookupAt(int fd, std::string_view path) {
  // If absolute path, ignore dir FD
  if (path[0] == '/') return Lookup(path);

  // Otherwise lookup relative to the dir FD
  std::shared_ptr<IDir> dir;
  if (fd == AT_FDCWD) {
    FSRoot &fs = myproc().get_filesystem();
    dir = fs.get_cwd();
  } else {
    FileTable &ftbl = myproc().get_file_table();
    File *f = ftbl.Get(fd);
    if (!f) return MakeError(EBADF);
    std::shared_ptr<Inode> ino = f->get_inode();
    if (!ino->is_dir()) return MakeError(ENOTDIR);
    dir = std::static_pointer_cast<IDir>(ino);
  }
  return LookupPath(dir, path);
}

Status<void> MkNod(Path path, mode_t mode, dev_t dev) {
  mode_t type = (mode & kTypeMask);

  auto [idir, name] = std::move(path);
  return idir->MkNod(name, mode, dev);
}

Status<void> MkDir(Path path, mode_t mode) {
  auto [idir, name] = std::move(path);
  return idir->MkDir(name, mode);
}

Status<void> Unlink(Path path) {
  auto [idir, name] = std::move(path);
  return idir->Unlink(name);
}

Status<void> RmDir(Path path) {
  auto [idir, name] = std::move(path);
  return idir->RmDir(name);
}

Status<void> SymLink(Path path, std::string_view target) {
  auto [idir, name] = std::move(path);
  return idir->SymLink(name, target);
}

Status<void> Rename(Path src_path, Path dst_path) {
  auto [src_idir, src_name] = std::move(src_path);
  auto [dst_idir, dst_name] = std::move(dst_path);
  return dst_idir->Rename(*src_idir, src_name, dst_name);
}

Status<void> Stat(Path path, struct stat *statbuf, bool chase_link = true) {
  auto [idir, name] = std::move(path);
  return ino->Stat(name);
}

}  // namespace

//
// System call implementation
//

int usys_mknod(const char *pathname, mode_t mode, dev_t dev) {
  Status<Path> path = Lookup(pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = MkNod(std::move(*path), mode, dev);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev) {
  Status<Path> path = LookupAt(dirfd, pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = MkNod(std::move(*path), mode, dev);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_mkdir(const char *pathname, mode_t mode) {
  Status<Path> path = Lookup(pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = MkDir(std::move(*path), mode);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_mkdirat(int dirfd, const char *pathname, mode_t mode) {
  Status<Path> path = LookupAt(dirfd, pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = MkDir(std::move(*path), mode);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_unlink(const char *pathname) {
  Status<Path> path = Lookup(pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = Unlink(std::move(*path));
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_rmdir(const char *pathname) {
  Status<Path> path = Lookup(pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = RmDir(std::move(*path));
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_unlinkat(int dirfd, const char *pathname, int flags) {
  Status<Path> path = LookupAt(dirfd, pathname);
  if (!path) return MakeCError(path);

  // Check if unlinking a directory.
  if ((flags & AT_REMOVEDIR) > 0) {
    Status<void> ret = RmDir(std::move(*path));
    if (!ret) return MakeCError(ret);
    return 0;
  }

  // Otherwise unlinking another type of file.
  Status<void> ret = Unlink(std::move(*path));
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_symlink(const char *target, const char *pathname) {
  Status<Path> path = Lookup(pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = SymLink(std::move(*path), target);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_symlinkat(const char *target, int dirfd, const char *pathname) {
  Status<Path> path = LookupAt(dirfd, pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = SymLink(std::move(*path), target);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_rename(const char *oldpath, const char *newpath) {
  Status<Path> src_path = Lookup(oldpath);
  if (!src_path) return MakeCError(src_path);
  Status<Path> dst_path = Lookup(newpath);
  if (!dst_path) return MakeCError(dst_path);
  Status<void> ret = Rename(std::move(*src_path), std::move(*dst_path));
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_renameat(int olddirfd, const char *oldpath, int newdirfd,
                  const char *newpath) {
  Status<Path> src_path = LookupAt(olddirfd, oldpath);
  if (!src_path) return MakeCError(src_path);
  Status<Path> dst_path = LookupAt(newdirfd, newpath);
  if (!dst_path) return MakeCError(dst_path);
  Status<void> ret = Rename(std::move(*src_path), std::move(*dst_path));
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_renameat2(int olddirfd, const char *oldpath, int newdirfd,
                   const char *newpath, unsigned int flags);

int usys_stat(const char *pathname, struct stat *statbuf) {
  Status<Path> path = Lookup(pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = Stat(path, statbuf);
  if (!ret) return MakeCError(ret);
  return 0;
}

}  // namespace junction
