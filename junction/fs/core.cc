// core.cc - core file system support

#include <algorithm>
#include <spanstream>
#include <utility>

#include "junction/base/string.h"
#include "junction/fs/file.h"
#include "junction/fs/fs.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

FSRoot *FSRoot::global_root_ = nullptr;

namespace {

using Path = std::pair<std::shared_ptr<IDir>, std::string_view>;
inline constexpr size_t kMaxLinkDepth = 40;

// NameIsValid determines if a file name has valid characters
constexpr bool NameIsValid(std::string_view name) {
  return std::none_of(std::cbegin(name), std::cend(name),
                      [](char c) { return c == '/' || c == '\0'; });
}

// Gets Inode for @path rooted at @dir. This is the core directory walking
// function.
Status<std::shared_ptr<Inode>> ResolvePath(const FSRoot &fs,
                                           std::shared_ptr<IDir> dir,
                                           std::string_view path,
                                           bool chase_last = true) {
  if (unlikely(path.empty())) return MakeError(EINVAL);

  std::vector<std::string_view> pathq = split(path, '/');
  std::reverse(pathq.begin(), pathq.end());

  // keep vector of strings so we can add string_views to pathq
  std::vector<std::string> symlinks;

  while (pathq.size()) {
    std::string_view v = pathq.back();
    pathq.pop_back();
    if (v.empty() || v == ".") continue;
    if (v == "..") {
      dir = dir->get_parent();
      continue;
    }

    Status<std::shared_ptr<Inode>> ret = dir->Lookup(v);
    if (!ret) return MakeError(ret);

    Inode &ino = *ret->get();

    // Read a symlink and add it to the pathq.
    if (ino.is_symlink() && (chase_last || !pathq.empty())) {
      if (symlinks.size() == kMaxLinkDepth) return MakeError(ELOOP);
      ISoftLink &link = static_cast<ISoftLink &>(ino);
      Status<std::string> l = link.ReadLink();
      if (unlikely(!l)) return MakeError(l);
      symlinks.push_back(std::move(*l));
      if (symlinks.back()[0] == '/') dir = fs.get_root();
      std::vector<std::string_view> lpath = split(symlinks.back(), '/');
      pathq.insert(pathq.end(), lpath.rbegin(), lpath.rend());
      continue;
    }

    // We hit the last inode, return it.
    if (pathq.empty()) {
      if (ino.is_stale()) return MakeError(ESTALE);
      return std::move(*ret);
    }

    if (!ino.is_dir()) return MakeError(ENOTDIR);
    dir = std::static_pointer_cast<IDir>(std::move(*ret));
  }

  // If we finished processing the pathq, return the current directory.
  if (dir->is_stale()) return MakeError(ESTALE);
  return dir;
}

// Lookup converts a path into a directory inode and the entry name.
Status<Path> Lookup(const FSRoot &fs, std::shared_ptr<IDir> dir,
                    std::string_view path) {
  std::vector<std::string_view> spath = rsplit(path, '/', 1);
  if (spath.size() == 1) return Path(std::move(dir), spath.front());

  assert(spath.size() == 2);

  std::string_view name = spath.back();
  if (!NameIsValid(name)) return MakeError(EINVAL);

  Status<std::shared_ptr<Inode>> ret = ResolvePath(fs, dir, spath.front());
  if (!ret) return MakeError(ret);

  Inode &ino = *ret->get();
  if (!ino.is_dir()) return MakeError(ENOTDIR);
  return Path(std::static_pointer_cast<IDir>(std::move(*ret)), name);
}

inline Status<std::shared_ptr<Inode>> FdToInode(int fd,
                                                Process &proc = myproc()) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (!f) return MakeError(EBADF);
  return f->get_inode();
}

// Get an IDir from a dirfd.
Status<std::shared_ptr<IDir>> DirFdToIDir(const FSRoot &fs, int dirfd) {
  if (dirfd == kAtFdCwd) return fs.get_cwd();
  Status<std::shared_ptr<Inode>> ino = FdToInode(dirfd);
  if (!ino) return MakeError(EBADF);
  std::shared_ptr<Inode> &iptr = *ino;
  if (!iptr->is_dir()) return MakeError(ENOTDIR);
  return std::static_pointer_cast<IDir>(std::move(*ino));
}

// LookupInode gets an inode from an absolute path.
Status<std::shared_ptr<Inode>> LookupInode(std::string_view path, bool chase) {
  FSRoot &fs = myproc().get_filesystem();
  std::shared_ptr<IDir> dir = path[0] == '/' ? fs.get_root() : fs.get_cwd();
  return ResolvePath(fs, std::move(dir), path, chase);
}

// LookupPath finds a directory inode and entry name starting from an absolute
// path
Status<Path> LookupPath(const FSRoot &fs, std::string_view path) {
  std::shared_ptr<IDir> dir = path[0] == '/' ? fs.get_root() : fs.get_cwd();
  return Lookup(fs, std::move(dir), path);
}

// LookupAt finds a directory inode and entry name starting from a directory FD
Status<Path> LookupAt(const FSRoot &fs, int fd, std::string_view path) {
  // If absolute path, ignore dir FD
  if (path[0] == '/') return LookupPath(fs, path);

  // Otherwise lookup relative to the dir FD
  Status<std::shared_ptr<IDir>> dir = DirFdToIDir(fs, fd);
  if (!dir) return MakeError(dir);
  return Lookup(fs, std::move(*dir), path);
}

Status<void> MkNod(Path path, mode_t mode, dev_t dev) {
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

Status<void> HardLink(std::shared_ptr<Inode> src, Path dst_path) {
  if (src->is_dir()) return MakeError(EPERM);
  auto [dst_idir, dst_name] = std::move(dst_path);
  return dst_idir->Link(dst_name, std::move(src));
}

Status<std::shared_ptr<File>> Open(const FSRoot &fs, Path path, int flags,
                                   mode_t mode) {
  auto [idir, name] = std::move(path);

  if (name.size() == 0) {
    if (flags & kFlagExclusive) return MakeError(EINVAL);
    return idir->Open(mode, flags);
  }

  Status<std::shared_ptr<Inode>> in = idir->Lookup(name);
  if (!in) {
    if (!(flags & kFlagCreate)) return MakeError(ENOENT);
    return idir->Create(name, mode);
  }

  if (flags & kFlagExclusive) return MakeError(EEXIST);
  if ((*in)->is_symlink()) {
    if ((flags & (kFlagNoFollow | kFlagPath)) == kFlagNoFollow)
      return MakeError(ELOOP);
    in = ResolvePath(fs, std::move(idir), name, true);
    if (!in) return MakeError(in);
  }
  return (*in)->Open(mode, flags);
}

}  // namespace

// Attempts to get the fullpath from the root of the filesystem to this IDir by
// traversing the chain of parents. The result is placed in @dst and an updated
// span is returned.
Status<std::span<char>> IDir::GetFullPath(const FSRoot &fs,
                                          std::span<char> dst) {
  std::shared_ptr<IDir> cur = get_this();
  std::vector<std::string> paths;
  while (true) {
    ParentPointer p = cur->get_parent_info();
    if (!p.parent || p.parent.get() == cur.get()) break;
    paths.emplace_back(std::move(p.name_in_parent));
    cur = std::move(p.parent);
  }

  std::ospanstream out(dst);
  for (auto it = paths.rend(); it != paths.rbegin(); it++) {
    if (static_cast<size_t>(out.tellp()) + 1 + it->size() >= dst.size())
      return MakeError(ERANGE);
    out << "/" << *it;
  }
  if (paths.size() == 0) {
    out << "/";
  }

  // Check that path is still valid.
  std::string_view s(out.span().data(), out.span().size());
  if (!ResolvePath(fs, cur, s)) return MakeError(ESTALE);

  return out.span();
}

// FSLookup finds and returns a reference to the inode for a path.
Status<std::shared_ptr<Inode>> FSLookup(const FSRoot &root,
                                        std::string_view path,
                                        bool chase_link) {
  std::shared_ptr<IDir> dir = path[0] == '/' ? root.get_root() : root.get_cwd();
  return ResolvePath(root, std::move(dir), path, chase_link);
}

// FSLookupAt finds and returns a reference to the inode for a path using a
// dirfd.
Status<std::shared_ptr<Inode>> FSLookupAt(const FSRoot &fs, int dirfd,
                                          std::string_view path,
                                          bool chase_link) {
  Status<std::shared_ptr<IDir>> dir = DirFdToIDir(fs, dirfd);
  if (!dir) return MakeError(dir);
  return ResolvePath(fs, std::move(*dir), path, chase_link);
}

//
// System call implementation
//

int usys_mknod(const char *pathname, mode_t mode, dev_t dev) {
  FSRoot &fs = myproc().get_filesystem();
  Status<Path> path = LookupPath(fs, pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = MkNod(std::move(*path), mode, dev);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev) {
  FSRoot &fs = myproc().get_filesystem();
  Status<Path> path = LookupAt(fs, dirfd, pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = MkNod(std::move(*path), mode, dev);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_mkdir(const char *pathname, mode_t mode) {
  FSRoot &fs = myproc().get_filesystem();
  Status<Path> path = LookupPath(fs, pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = MkDir(std::move(*path), mode);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_mkdirat(int dirfd, const char *pathname, mode_t mode) {
  FSRoot &fs = myproc().get_filesystem();
  Status<Path> path = LookupAt(fs, dirfd, pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = MkDir(std::move(*path), mode);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_unlink(const char *pathname) {
  FSRoot &fs = myproc().get_filesystem();
  Status<Path> path = LookupPath(fs, pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = Unlink(std::move(*path));
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_rmdir(const char *pathname) {
  FSRoot &fs = myproc().get_filesystem();
  Status<Path> path = LookupPath(fs, pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = RmDir(std::move(*path));
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_unlinkat(int dirfd, const char *pathname, int flags) {
  FSRoot &fs = myproc().get_filesystem();
  Status<Path> path = LookupAt(fs, dirfd, pathname);
  if (!path) return MakeCError(path);

  // Check if unlinking a directory.
  if ((flags & kAtRemoveDir) > 0) {
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
  FSRoot &fs = myproc().get_filesystem();
  Status<Path> path = LookupPath(fs, pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = SymLink(std::move(*path), target);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_symlinkat(const char *target, int dirfd, const char *pathname) {
  FSRoot &fs = myproc().get_filesystem();
  Status<Path> path = LookupAt(fs, dirfd, pathname);
  if (!path) return MakeCError(path);
  Status<void> ret = SymLink(std::move(*path), target);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_rename(const char *oldpath, const char *newpath) {
  FSRoot &fs = myproc().get_filesystem();
  Status<Path> src_path = LookupPath(fs, oldpath);
  if (!src_path) return MakeCError(src_path);
  Status<Path> dst_path = LookupPath(fs, newpath);
  if (!dst_path) return MakeCError(dst_path);
  Status<void> ret = Rename(std::move(*src_path), std::move(*dst_path));
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_renameat(int olddirfd, const char *oldpath, int newdirfd,
                  const char *newpath) {
  FSRoot &fs = myproc().get_filesystem();
  Status<Path> src_path = LookupAt(fs, olddirfd, oldpath);
  if (!src_path) return MakeCError(src_path);
  Status<Path> dst_path = LookupAt(fs, newdirfd, newpath);
  if (!dst_path) return MakeCError(dst_path);
  Status<void> ret = Rename(std::move(*src_path), std::move(*dst_path));
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_renameat2(int olddirfd, const char *oldpath, int newdirfd,
                   const char *newpath, unsigned int flags) {
  FSRoot &fs = myproc().get_filesystem();
  // TODO(amb): no flags are supported so far.
  if (flags != 0) return -EINVAL;
  Status<Path> src_path = LookupAt(fs, olddirfd, oldpath);
  if (!src_path) return MakeCError(src_path);
  Status<Path> dst_path = LookupAt(fs, newdirfd, newpath);
  if (!dst_path) return MakeCError(dst_path);
  Status<void> ret = Rename(std::move(*src_path), std::move(*dst_path));
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
  FSRoot &fs = myproc().get_filesystem();
  Status<Path> p = LookupAt(fs, dirfd, pathname);
  if (!p) return MakeCError(p);
  Status<std::shared_ptr<File>> f = Open(fs, std::move(*p), flags, mode);
  if (!f) return MakeCError(f);
  FileTable &ftbl = myproc().get_file_table();
  return ftbl.Insert(std::move(*f), (flags & kFlagCloseExec) > 0);
}

long usys_open(const char *pathname, int flags, mode_t mode) {
  FSRoot &fs = myproc().get_filesystem();
  Status<Path> p = LookupPath(fs, pathname);
  if (!p) return MakeCError(p);
  Status<std::shared_ptr<File>> f = Open(fs, std::move(*p), flags, mode);
  if (!f) return MakeCError(f);
  FileTable &ftbl = myproc().get_file_table();
  return ftbl.Insert(std::move(*f), (flags & kFlagCloseExec) > 0);
}

long usys_link(const char *oldpath, const char *newpath) {
  FSRoot &fs = myproc().get_filesystem();
  Status<std::shared_ptr<Inode>> inode = FSLookup(fs, oldpath);
  if (!inode) return MakeCError(inode);
  Status<Path> newp = LookupPath(fs, newpath);
  if (!newp) return MakeCError(newp);
  Status<void> ret = HardLink(std::move(*inode), std::move(*newp));
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_linkat(int olddirfd, const char *oldpath, int newdirfd,
                 const char *newpath, int flags) {
  FSRoot &fs = myproc().get_filesystem();
  std::string_view oldpathv(oldpath);
  Status<std::shared_ptr<Inode>> inode;
  if ((flags & kAtEmptyPath) && oldpathv.size() == 0) {
    inode = FdToInode(olddirfd);
  } else {
    bool chase_link = (flags & kAtFollowLink) != 0;
    inode = FSLookupAt(fs, olddirfd, oldpathv, chase_link);
  }
  if (!inode) return MakeCError(inode);
  Status<Path> newp = LookupPath(fs, newpath);
  if (!newp) return MakeCError(newp);
  Status<void> ret = HardLink(std::move(*inode), std::move(*newp));
  if (!ret) return MakeCError(ret);
  return 0;
}

long AccessCheck(Inode &inode, mode_t mode) {
  if (mode == F_OK) return 0;
  mode_t imode = inode.get_mode();
  if ((mode & R_OK) && !(imode & S_IRUSR)) return -EACCES;
  if ((mode & W_OK) && !(imode & S_IWUSR)) return -EACCES;
  if ((mode & X_OK) && !(imode & S_IXUSR)) return -EACCES;
  return 0;
}

long usys_access(const char *pathname, int mode) {
  FSRoot &root = myproc().get_filesystem();
  Status<std::shared_ptr<Inode>> tmp = FSLookup(root, pathname);
  if (!tmp) return MakeCError(tmp);
  return AccessCheck(*tmp->get(), mode);
}

long usys_faccessat(int dirfd, const char *pathname, int mode) {
  FSRoot &fs = myproc().get_filesystem();
  Status<std::shared_ptr<Inode>> tmp = FSLookupAt(fs, dirfd, pathname);
  if (!tmp) return MakeCError(tmp);
  return AccessCheck(*tmp->get(), mode);
}

long usys_faccessat2(int dirfd, const char *pathname, int mode, int flags) {
  FSRoot &fs = myproc().get_filesystem();
  bool chase_link = !(flags & kAtNoFollowLink);
  Status<std::shared_ptr<Inode>> tmp =
      FSLookupAt(fs, dirfd, pathname, chase_link);
  if (!tmp) return MakeCError(tmp);
  return AccessCheck(*tmp->get(), mode);
}

Status<long> DoReadLink(Inode &ino, std::span<std::byte> dst) {
  if (!ino.is_symlink()) return MakeError(EINVAL);
  Status<std::string> link = static_cast<ISoftLink &>(ino).ReadLink();
  if (!link) return MakeError(link);
  size_t copy = std::min(dst.size(), link->size());
  std::memcpy(dst.data(), link->data(), copy);
  return copy;
}

ssize_t usys_readlinkat(int dirfd, const char *pathname, char *buf,
                        size_t bufsiz) {
  std::string_view p(pathname);

  if (p == "/proc/self/exe") {
    auto str = myproc().get_bin_path();
    size_t copy = std::min(bufsiz, str.size());
    return copy;
  }

  Status<long> ret;

  if (p.empty()) {
    FileTable &ftbl = myproc().get_file_table();
    File *f = ftbl.Get(dirfd);
    if (unlikely(!f)) return -EBADF;
    ret = f->ReadLink(readable_span(buf, bufsiz));
  } else {
    FSRoot &fs = myproc().get_filesystem();
    Status<std::shared_ptr<Inode>> tmp = FSLookupAt(fs, dirfd, pathname, false);
    if (!tmp) return MakeCError(tmp);
    ret = DoReadLink(*tmp->get(), readable_span(buf, bufsiz));
  }

  if (!ret) return MakeCError(ret);
  return *ret;
}

ssize_t usys_readlink(const char *pathname, char *buf, size_t bufsiz) {
  std::string_view p(pathname);
  // TODO(jf): remove this when ready.
  if (p == "/proc/self/exe") {
    auto str = myproc().get_bin_path();
    size_t copy = std::min(bufsiz, str.size());
    return copy;
  }

  FSRoot &root = myproc().get_filesystem();
  Status<std::shared_ptr<Inode>> tmp = FSLookup(root, pathname, false);
  if (!tmp) return MakeCError(tmp);
  Status<long> ret = DoReadLink(*tmp->get(), readable_span(buf, bufsiz));
  if (!ret) return MakeCError(ret);
  return *ret;
}

long usys_getcwd(char *buf, size_t size) {
  FSRoot &fs = myproc().get_filesystem();
  Status<std::span<char>> pth =
      fs.get_cwd()->GetFullPath(fs, std::span<char>(buf, size - 1));
  if (!pth) return MakeCError(pth);
  buf[pth->size()] = '\0';
  return pth->size() + 1;
}

long usys_chdir(const char *pathname) {
  Status<std::shared_ptr<Inode>> ino = LookupInode(pathname, true);
  if (!ino) return MakeCError(ino);
  if (!(*ino)->is_dir()) return -ENOTDIR;
  myproc().get_filesystem().SetCwd(
      std::static_pointer_cast<IDir>(std::move(*ino)));
  return 0;
}

long usys_fchdir(int fd) {
  Status<std::shared_ptr<Inode>> ino = FdToInode(fd);
  if (!ino) return -EBADF;
  std::shared_ptr<Inode> &iptr = *ino;
  if (!iptr->is_dir()) return -ENOTDIR;
  myproc().get_filesystem().SetCwd(
      std::static_pointer_cast<IDir>(std::move(*ino)));
  return 0;
}

long usys_stat(const char *path, struct stat *statbuf) {
  Status<std::shared_ptr<Inode>> tmp = LookupInode(path, true);
  if (!tmp) return MakeCError(tmp);
  Status<void> stat = (*tmp)->GetStats(statbuf);
  if (!stat) return MakeCError(stat);
  return 0;
}

long usys_lstat(const char *path, struct stat *statbuf) {
  Status<std::shared_ptr<Inode>> tmp = LookupInode(path, false);
  if (!tmp) return MakeCError(tmp);
  Status<void> stat = (*tmp)->GetStats(statbuf);
  if (!stat) return MakeCError(stat);
  return 0;
}

long usys_statfs(const char *path, struct statfs *buf) {
  Status<std::shared_ptr<Inode>> tmp = LookupInode(path, false);
  if (!tmp) return MakeCError(tmp);
  Status<void> stat = (*tmp)->GetStatFS(buf);
  if (!stat) return MakeCError(stat);
  return 0;
}

Status<void> InitFs() {
  // For now set the root to the linux FS mount point.
  Status<std::shared_ptr<IDir>> linuxfs = linuxfs::InitLinuxFs();
  if (!linuxfs) return MakeError(linuxfs);
  (*linuxfs)->inc_nlink();
  // root's parent is itself.
  (*linuxfs)->DoRename(*linuxfs, ".");
  FSRoot::InitFsRoot(std::move(*linuxfs));
  return {};
}

}  // namespace junction
