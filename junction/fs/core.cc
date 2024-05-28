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

// The maximum number of links to follow before giving up with ELOOP
inline constexpr size_t kMaxLinksToChase = 8;

// PathIsValid determines if a file path has valid characters
constexpr bool PathIsValid(std::string_view path) {
  return std::none_of(std::cbegin(path), std::cend(path),
                      [](char c) { return c == '\0'; });
}

// WalkPath uses UNIX path resolution to find an inode (if it exists)
// See the path_resolution(7) manual page for more details.
Status<std::shared_ptr<Inode>> WalkPath(
    const FSRoot &fs, std::shared_ptr<IDir> dir,
    const std::vector<std::string_view> &path, bool chase_last = true,
    int link_depth = kMaxLinksToChase) {
  if (link_depth <= 0) return MakeError(ELOOP);

  for (auto it = path.begin(); it != path.end(); it++) {
    const std::string_view &v = *it;

    if (v.empty() || v == ".") continue;
    if (v == "..") {
      dir = dir->get_parent();
      continue;
    }

    Status<std::shared_ptr<Inode>> ret = dir->Lookup(v);
    if (!ret) return MakeError(ret);

    Inode *ino = ret->get();

    bool last_component = it + 1 == path.end();

    if (ino->is_symlink() && (chase_last || !last_component)) {
      auto &link = static_cast<ISoftLink &>(*ino);
      std::string lpath = link.ReadLink();
      std::shared_ptr<IDir> newroot = lpath[0] == '/' ? fs.get_root() : dir;
      ret = WalkPath(fs, std::move(newroot), split(lpath, '/'), true,
                     link_depth - 1);
      if (!ret) return MakeError(ret);
      ino = ret->get();
    }

    // We hit the last inode, return it.
    if (last_component) {
      if (ino->is_stale()) return MakeError(ESTALE);
      return std::move(*ret);
    }

    if (!ino->is_dir()) return MakeError(ENOTDIR);
    dir = std::static_pointer_cast<IDir>(std::move(*ret));
  }

  // The last component could have been a "..".
  if (dir->is_stale()) return MakeError(ESTALE);
  return dir;
}

// SplitPath converts a path into an array of names. @must_be_dir is set if the
// path specifies a directory. Otherwise, the path could be any type of inode
// (including a directory).
std::vector<std::string_view> SplitPath(std::string_view path,
                                        bool *must_be_dir) {
  std::vector<std::string_view> spath = split(path, '/');
  auto it = std::find_if(
      spath.rbegin(), spath.rend(),
      [](std::string_view str) { return !str.empty() && str != "."; });
  if (must_be_dir) *must_be_dir = it != spath.rbegin();
  spath.erase(it.base(), std::end(spath));
  return spath;
}

// GetPathDir returns the first directory in a path
inline std::shared_ptr<IDir> GetPathDir(const FSRoot &fs,
                                        std::string_view path) {
  return path[0] == '/' ? fs.get_root() : fs.get_cwd();
}

inline Status<std::shared_ptr<Inode>> GetFileInode(int fd,
                                                   Process &proc = myproc()) {
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (!f) return MakeError(EBADF);
  return f->get_inode();
}

// GetPathDirAt returns the first directory in a path relative to an FD
Status<std::shared_ptr<IDir>> GetPathDirAt(Process &p, int fd,
                                           std::string_view path) {
  // If absolute path, ignore the directory FD
  if (path[0] == '/') return p.get_fs().get_root();

  // Check if the directory FD specifies the CWD
  if (fd == kAtFdCwd) return p.get_fs().get_cwd();

  // Lookup relative to the directory FD
  FileTable &ftbl = p.get_file_table();
  File *f = ftbl.Get(fd);
  if (!f) return MakeError(EBADF);
  std::shared_ptr<Inode> ino = f->get_inode();
  if (!ino->is_dir()) return MakeError(ENOTDIR);
  return std::static_pointer_cast<IDir>(std::move(ino));
}

// Entry bundles together path resolution data (needed by most system calls)
struct Entry {
  std::shared_ptr<IDir> dir;
  std::string_view name;
  bool must_be_dir;
};

// LookupEntry finds an entry for a path relative to a starting directory
Status<Entry> LookupEntry(const FSRoot &fs, std::shared_ptr<IDir> pos,
                          std::string_view path) {
  if (!PathIsValid(path)) return MakeError(EINVAL);
  bool must_be_dir;
  std::vector<std::string_view> spath = SplitPath(path, &must_be_dir);

  // special case for '/' or '.'
  if (spath.size() == 0) return Entry{std::move(pos), {}, true};

  std::string_view name = spath.back();
  spath.pop_back();
  Status<std::shared_ptr<Inode>> ret = WalkPath(fs, std::move(pos), spath);
  if (!ret) return MakeError(ret);
  if (!(*ret)->is_dir()) return MakeError(ENOTDIR);

  if (name == "..") {
    IDir &dir = static_cast<IDir &>(*ret->get());
    return Entry{dir.get_parent(), {}, true};
  }

  if (name == ".") name = {};
  return Entry{std::static_pointer_cast<IDir>(std::move(*ret)), name,
               must_be_dir};
}

// LookupEntry finds an entry for a path
Status<Entry> LookupEntry(const FSRoot &fs, std::string_view path) {
  return LookupEntry(fs, GetPathDir(fs, path), path);
}

// LookupEntry finds an entry for a path relative to an FD
Status<Entry> LookupEntry(Process &p, int fd, std::string_view path) {
  Status<std::shared_ptr<IDir>> pathd = GetPathDirAt(p, fd, path);
  if (!pathd) return MakeError(pathd);
  return LookupEntry(p.get_fs(), std::move(*pathd), path);
}

Status<void> MkNod(const Entry &entry, mode_t mode, dev_t dev) {
  mode_t type = (mode & kTypeMask);
  if (entry.must_be_dir) return MakeError(EISDIR);
  return entry.dir->MkNod(entry.name, mode, dev);
}

Status<void> MkDir(const Entry &entry, mode_t mode) {
  return entry.dir->MkDir(entry.name, mode);
}

Status<void> Unlink(const Entry &entry) {
  if (entry.must_be_dir) return MakeError(EISDIR);
  return entry.dir->Unlink(entry.name);
}

Status<void> RmDir(const Entry &entry) { return entry.dir->RmDir(entry.name); }

Status<void> SymLink(const Entry &entry, std::string_view target) {
  if (entry.must_be_dir) return MakeError(EISDIR);
  if (!PathIsValid(target)) return MakeError(EINVAL);
  return entry.dir->SymLink(entry.name, target);
}

Status<void> Rename(const Entry &src_entry, const Entry &dst_entry) {
  auto &[src_idir, src_name, src_must_be_dir] = src_entry;
  auto &[dst_idir, dst_name, dst_must_be_dir] = dst_entry;
  return dst_idir->Rename(*src_idir, src_name, dst_name);
}

Status<void> HardLink(std::shared_ptr<Inode> src, const Entry &dst_path) {
  if (src->is_dir()) return MakeError(EPERM);
  auto &[dst_idir, dst_name, must_be_dir] = dst_path;
  return dst_idir->Link(dst_name, std::move(src));
}

Status<std::shared_ptr<File>> Open(const FSRoot &fs, const Entry &path,
                                   int flags, mode_t mode) {
  auto &[idir, name, must_be_dir] = path;

  // Special case for "/"
  if (!name.size()) {
    if (flags & kFlagExclusive) return MakeError(EINVAL);
    return idir->Open(mode, flags);
  }

  Status<std::shared_ptr<Inode>> in = idir->Lookup(name);
  if (!in) {
    if (!(flags & kFlagCreate)) return MakeError(ENOENT);
    return idir->Create(name, flags, mode & ~fs.get_umask());
  }

  if (flags & kFlagExclusive) return MakeError(EEXIST);
  if ((*in)->is_symlink()) {
    if ((flags & (kFlagNoFollow | kFlagPath)) == kFlagNoFollow)
      return MakeError(ELOOP);
    in = WalkPath(fs, std::move(idir), {name}, true);
    if (!in) return MakeError(in);
  }
  return (*in)->Open(mode, flags);
}

}  // namespace

// LookupInode finds an inode for a path
Status<std::shared_ptr<Inode>> LookupInode(const FSRoot &fs,
                                           std::string_view path,
                                           bool chase_link) {
  if (!PathIsValid(path)) return MakeError(EINVAL);
  std::vector<std::string_view> spath = SplitPath(path, nullptr);
  return WalkPath(fs, GetPathDir(fs, path), spath, chase_link);
}

// LookupInode finds an inode for a path
Status<std::shared_ptr<Inode>> LookupInode(Process &p, int dirfd,
                                           std::string_view path,
                                           bool chase_link) {
  if (!PathIsValid(path)) return MakeError(EINVAL);
  Status<std::shared_ptr<IDir>> pathd = GetPathDirAt(p, dirfd, path);
  if (!pathd) return MakeError(pathd);
  std::vector<std::string_view> spath = SplitPath(path, nullptr);
  return WalkPath(p.get_fs(), std::move(*pathd), spath, chase_link);
}

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
  if (!WalkPath(fs, std::move(cur), split(s, '/'))) return MakeError(ESTALE);

  return out.span();
}

//
// System call implementation
//

int usys_mknod(const char *pathname, mode_t mode, dev_t dev) {
  Status<Entry> entry = LookupEntry(myproc().get_fs(), pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = MkNod(*entry, mode, dev);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev) {
  Status<Entry> entry = LookupEntry(myproc(), dirfd, pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = MkNod(*entry, mode, dev);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_mkdir(const char *pathname, mode_t mode) {
  Status<Entry> entry = LookupEntry(myproc().get_fs(), pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = MkDir(*entry, mode);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_mkdirat(int dirfd, const char *pathname, mode_t mode) {
  Status<Entry> entry = LookupEntry(myproc(), dirfd, pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = MkDir(*entry, mode);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_unlink(const char *pathname) {
  Status<Entry> entry = LookupEntry(myproc().get_fs(), pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = Unlink(*entry);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_rmdir(const char *pathname) {
  Status<Entry> entry = LookupEntry(myproc().get_fs(), pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = RmDir(*entry);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_unlinkat(int dirfd, const char *pathname, int flags) {
  Status<Entry> entry = LookupEntry(myproc(), dirfd, pathname);
  if (!entry) return MakeCError(entry);

  // Check if unlinking a directory.
  if ((flags & kAtRemoveDir) > 0) {
    Status<void> ret = RmDir(*entry);
    if (!ret) return MakeCError(ret);
    return 0;
  }

  // Otherwise unlinking another type of file.
  Status<void> ret = Unlink(*entry);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_symlink(const char *target, const char *pathname) {
  Status<Entry> entry = LookupEntry(myproc().get_fs(), pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = SymLink(*entry, target);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_symlinkat(const char *target, int dirfd, const char *pathname) {
  Status<Entry> entry = LookupEntry(myproc(), dirfd, pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = SymLink(*entry, target);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_rename(const char *oldpath, const char *newpath) {
  FSRoot &fs = myproc().get_fs();
  Status<Entry> src_entry = LookupEntry(fs, oldpath);
  if (!src_entry) return MakeCError(src_entry);
  Status<Entry> dst_entry = LookupEntry(fs, newpath);
  if (!dst_entry) return MakeCError(dst_entry);
  Status<void> ret = Rename(*src_entry, *dst_entry);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_renameat(int olddirfd, const char *oldpath, int newdirfd,
                  const char *newpath) {
  Process &p = myproc();
  Status<Entry> src_entry = LookupEntry(p, olddirfd, oldpath);
  if (!src_entry) return MakeCError(src_entry);
  Status<Entry> dst_entry = LookupEntry(p, newdirfd, newpath);
  if (!dst_entry) return MakeCError(dst_entry);
  Status<void> ret = Rename(*src_entry, *dst_entry);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_renameat2(int olddirfd, const char *oldpath, int newdirfd,
                   const char *newpath, unsigned int flags) {
  // TODO(amb): no flags are supported so far.
  if (flags != 0) return -EINVAL;
  return usys_renameat(olddirfd, oldpath, newdirfd, newpath);
}

long usys_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
  Process &p = myproc();
  Status<Entry> entry = LookupEntry(p, dirfd, pathname);
  if (!entry) return MakeCError(entry);
  Status<std::shared_ptr<File>> f = Open(p.get_fs(), *entry, flags, mode);
  if (!f) return MakeCError(f);
  if (flags & kFlagAppend) {
    Status<off_t> ret = (*f)->Seek(0, SeekFrom::kEnd);
    if (!ret) return MakeCError(ret);
    (*f)->get_off_ref() = *ret;
  }
  FileTable &ftbl = p.get_file_table();
  return ftbl.Insert(std::move(*f), (flags & kFlagCloseExec) > 0);
}

long usys_open(const char *pathname, int flags, mode_t mode) {
  Process &p = myproc();
  FSRoot &fs = p.get_fs();
  Status<Entry> entry = LookupEntry(fs, pathname);
  if (!entry) return MakeCError(entry);
  Status<std::shared_ptr<File>> f = Open(fs, *entry, flags, mode);
  if (!f) return MakeCError(f);
  if (flags & kFlagAppend) {
    Status<off_t> ret = (*f)->Seek(0, SeekFrom::kEnd);
    if (!ret) return MakeCError(ret);
    (*f)->get_off_ref() = *ret;
  }
  FileTable &ftbl = p.get_file_table();
  return ftbl.Insert(std::move(*f), (flags & kFlagCloseExec) > 0);
}

long usys_link(const char *oldpath, const char *newpath) {
  FSRoot &fs = myproc().get_fs();
  Status<std::shared_ptr<Inode>> inode = LookupInode(fs, oldpath);
  if (!inode) return MakeCError(inode);
  Status<Entry> newp = LookupEntry(fs, newpath);
  if (!newp) return MakeCError(newp);
  Status<void> ret = HardLink(std::move(*inode), *newp);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_linkat(int olddirfd, const char *oldpath, int newdirfd,
                 const char *newpath, int flags) {
  std::string_view oldpathv(oldpath);
  Status<std::shared_ptr<Inode>> inode;
  Process &p = myproc();
  if ((flags & kAtEmptyPath) && oldpathv.size() == 0) {
    inode = GetFileInode(olddirfd);
  } else {
    bool chase_link = (flags & kAtFollowLink) != 0;
    inode = LookupInode(p, olddirfd, oldpathv, chase_link);
  }
  if (!inode) return MakeCError(inode);
  Status<Entry> newp = LookupEntry(p, newdirfd, newpath);
  if (!newp) return MakeCError(newp);
  Status<void> ret = HardLink(std::move(*inode), *newp);
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
  Status<std::shared_ptr<Inode>> tmp = LookupInode(myproc().get_fs(), pathname);
  if (!tmp) return MakeCError(tmp);
  return AccessCheck(*tmp->get(), mode);
}

long usys_faccessat(int dirfd, const char *pathname, int mode) {
  Status<std::shared_ptr<Inode>> tmp = LookupInode(myproc(), dirfd, pathname);
  if (!tmp) return MakeCError(tmp);
  return AccessCheck(*tmp->get(), mode);
}

long usys_faccessat2(int dirfd, const char *pathname, int mode, int flags) {
  bool chase_link = !(flags & kAtNoFollowLink);
  Status<std::shared_ptr<Inode>> tmp =
      LookupInode(myproc(), dirfd, pathname, chase_link);
  if (!tmp) return MakeCError(tmp);
  return AccessCheck(*tmp->get(), mode);
}

Status<long> DoReadLink(Inode &ino, std::span<std::byte> dst) {
  if (!ino.is_symlink()) return MakeError(EINVAL);
  std::string lpath = static_cast<ISoftLink &>(ino).ReadLink();
  size_t copy = std::min(dst.size(), lpath.size());
  std::memcpy(dst.data(), lpath.data(), copy);
  return copy;
}

ssize_t usys_readlinkat(int dirfd, const char *pathname, char *buf,
                        size_t bufsiz) {
  std::string_view p(pathname);

  if (p == "/proc/self/exe") {
    auto str = myproc().get_bin_path();
    size_t copy = std::min(bufsiz, str.size());
    std::memcpy(buf, str.data(), copy);
    return copy;
  }

  Status<long> ret;

  if (p.empty()) {
    FileTable &ftbl = myproc().get_file_table();
    File *f = ftbl.Get(dirfd);
    if (unlikely(!f)) return -EBADF;
    ret = f->ReadLink(readable_span(buf, bufsiz));
  } else {
    Status<std::shared_ptr<Inode>> tmp =
        LookupInode(myproc(), dirfd, pathname, false);
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
    std::memcpy(buf, str.data(), copy);
    return copy;
  }

  FSRoot &fs = myproc().get_fs();
  Status<std::shared_ptr<Inode>> tmp = LookupInode(fs, pathname, false);
  if (!tmp) return MakeCError(tmp);
  Status<long> ret = DoReadLink(*tmp->get(), readable_span(buf, bufsiz));
  if (!ret) return MakeCError(ret);
  return *ret;
}

long usys_getcwd(char *buf, size_t size) {
  FSRoot &fs = myproc().get_fs();
  Status<std::span<char>> pth =
      fs.get_cwd()->GetFullPath(fs, std::span<char>(buf, size - 1));
  if (!pth) return MakeCError(pth);
  buf[pth->size()] = '\0';
  return pth->size() + 1;
}

long usys_chdir(const char *pathname) {
  Process &p = myproc();
  Status<std::shared_ptr<Inode>> ino = LookupInode(p.get_fs(), pathname, true);
  if (!ino) return MakeCError(ino);
  if (!(*ino)->is_dir()) return -ENOTDIR;
  p.SetCwd(std::static_pointer_cast<IDir>(std::move(*ino)));
  return 0;
}

long usys_fchdir(int fd) {
  Process &p = myproc();
  Status<std::shared_ptr<Inode>> ino = GetFileInode(fd, p);
  if (!ino) return MakeCError(ino);
  if (!(*ino)->is_dir()) return -ENOTDIR;
  p.SetCwd(std::static_pointer_cast<IDir>(std::move(*ino)));
  return 0;
}

long usys_stat(const char *path, struct stat *statbuf) {
  FSRoot &fs = myproc().get_fs();
  Status<std::shared_ptr<Inode>> tmp = LookupInode(fs, path, true);
  if (!tmp) return MakeCError(tmp);
  Status<void> stat = (*tmp)->GetStats(statbuf);
  if (!stat) return MakeCError(stat);
  return 0;
}

long usys_lstat(const char *path, struct stat *statbuf) {
  FSRoot &fs = myproc().get_fs();
  Status<std::shared_ptr<Inode>> tmp = LookupInode(fs, path, false);
  if (!tmp) return MakeCError(tmp);
  Status<void> stat = (*tmp)->GetStats(statbuf);
  if (!stat) return MakeCError(stat);
  return 0;
}

long usys_statfs(const char *path, struct statfs *buf) {
  FSRoot &fs = myproc().get_fs();
  Status<std::shared_ptr<Inode>> tmp = LookupInode(fs, path, false);
  if (!tmp) return MakeCError(tmp);
  Status<void> stat = (*tmp)->GetStatFS(buf);
  if (!stat) return MakeCError(stat);
  return 0;
}

int usys_truncate(const char *path, off_t length) {
  FSRoot &fs = myproc().get_fs();
  Status<std::shared_ptr<Inode>> tmp = LookupInode(fs, path, true);
  if (!tmp) return MakeCError(tmp);
  Inode &ino = *tmp->get();
  if (!ino.is_regular()) return -EINVAL;
  Status<void> ret = ino.SetSize(static_cast<size_t>(length));
  if (!ret) return MakeCError(ret);
  return 0;
}

// Recursively visit all directories under root.
void Recurse(std::shared_ptr<IDir> root) {
  std::vector<std::shared_ptr<IDir>> queue;
  queue.emplace_back(std::move(root));

  while (queue.size()) {
    std::shared_ptr<IDir> id = std::move(queue.back());
    queue.pop_back();
    for (auto &entry : id->GetDents()) {
      Status<std::shared_ptr<Inode>> in = id->Lookup(entry.name);
      if (!in || !(*in)->is_dir()) continue;
      queue.emplace_back(std::static_pointer_cast<IDir>(std::move(*in)));
    }
  }
}

// Ensures all folders in path of @path exist, creating memfs folders as needed.
Status<Entry> SetupMountPoint(std::shared_ptr<IDir> pos,
                              std::string_view path) {
  std::vector<std::string_view> s = SplitPath(path, nullptr);
  if (!s.size()) return MakeError(EINVAL);
  std::string_view name = s.back();
  s.pop_back();

  auto it = s.begin();
  for (; it != s.end(); it++) {
    const std::string_view &v = *it;
    if (v == "." || v == "..") {
      LOG(ERR) << "mount point path must be normal: " << path;
      return MakeError(EINVAL);
    }
    if (v.empty()) continue;
    Status<std::shared_ptr<Inode>> next = pos->Lookup(v);
    if (!next || !(*next)->is_dir()) break;
    pos = std::static_pointer_cast<IDir>(std::move(*next));
  }

  // Insert memfs directories as needed.
  for (; it != s.end(); it++) {
    std::shared_ptr<IDir> memfs = memfs::MkFolder();
    pos->Mount(std::string(*it), memfs);
    pos = std::move(memfs);
  }

  return Entry{std::move(pos), name, true};
}

// Mounts a memfs filesystem rooted at @pos specified by @pathname.
Status<void> MemFSMount(std::shared_ptr<IDir> pos, std::string_view mp) {
  Status<Entry> tmp = SetupMountPoint(pos, mp);
  if (!tmp) return MakeError(tmp);
  auto &[dir, name, must_be_dir] = *tmp;
  std::shared_ptr<IDir> memfs = memfs::MkFolder();
  dir->Mount(std::string(name), memfs);
  return {};
}

// Mounts a linux fs rooted at @pos specified by @pathname from @host_path.
Status<void> LinuxFSMount(std::shared_ptr<IDir> pos,
                          std::string_view mount_point,
                          std::string_view host_path) {
  Status<Entry> tmp = SetupMountPoint(pos, mount_point);
  if (!tmp) return MakeError(tmp);
  auto &[dir, name, must_be_dir] = *tmp;

  Status<std::shared_ptr<IDir>> mount = linuxfs::MountLinux(host_path);
  if (!mount) return MakeError(mount);
  dir->Mount(std::string(name), std::move(*mount));
  return {};
}

Status<void> InitFs(
    const std::vector<std::pair<std::string, std::string>> &linux_mount_points,
    const std::vector<std::string> &mem_mount_points) {
  // Set the root to the linux FS mount point.
  Status<std::shared_ptr<IDir>> tmp = linuxfs::InitLinuxRoot();
  if (!tmp) return MakeError(tmp);
  IDir &linux_root = *tmp->get();
  linux_root.inc_nlink();
  // root's parent is itself.
  linux_root.SetParent(*tmp, ".");

  // Mount any additional linux mountpoints/filesystems.
  for (const auto &[mount_path, host_path] : linux_mount_points) {
    if (Status<void> ret = LinuxFSMount(*tmp, mount_path, host_path); !ret)
      return MakeError(ret);
  }

  // Enumerate all Linux folders to cache dents.
  if (GetCfg().cache_linux_fs()) Recurse(*tmp);

  // Mount the default memfs directory.
  if (Status<void> ret = MemFSMount(*tmp, "/memfs"); !ret) return ret;

  // Mount user requested memfs paths.
  for (const std::string &p : mem_mount_points) {
    if (Status<void> ret = MemFSMount(*tmp, p); !ret) return ret;
  }

  FSRoot::InitFsRoot(std::move(*tmp));
  return {};
}

}  // namespace junction
