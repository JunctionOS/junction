// core.cc - core file system support

#include <algorithm>
#include <spanstream>
#include <utility>

#include "junction/base/string.h"
#include "junction/fs/dev.h"
#include "junction/fs/file.h"
#include "junction/fs/fs.h"
#include "junction/fs/procfs/procfs.h"
#include "junction/fs/stdiofile.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

FSRoot *FSRoot::global_root_ = nullptr;

namespace {

static std::atomic_size_t inos;

// The maximum number of links to follow before giving up with ELOOP
inline constexpr size_t kMaxLinksToChase = 8;

// PathIsValid determines if a file path has valid characters
constexpr bool PathIsValid(std::string_view path) {
  return std::none_of(std::cbegin(path), std::cend(path),
                      [](char c) { return c == '\0'; });
}

// WalkPath uses UNIX path resolution to find an inode (if it exists)
// See the path_resolution(7) manual page for more details.
Status<std::shared_ptr<DirectoryEntry>> WalkPath(
    const FSRoot &fs, std::shared_ptr<IDir> dir,
    const std::vector<std::string_view> &path, bool chase_last = true,
    int link_depth = kMaxLinksToChase) {
  if (link_depth <= 0) return MakeError(ELOOP);

  std::shared_ptr<DirectoryEntry> curent = dir->get_entry();
  IDir *curdir = dir.get();

  for (const std::string_view &v : path) {
    if (v.empty() || v == ".") continue;
    if (v == "..") {
      curent = curent->get_parent_ent();
      curdir = static_cast<IDir *>(&curent->get_inode_ref());
      continue;
    }

    Status<std::shared_ptr<DirectoryEntry>> ret = curdir->LookupDent(v);
    if (!ret) return MakeError(ret);

    Inode *ino = &(*ret)->get_inode_ref();
    if (ino->is_stale()) return MakeError(ESTALE);

    bool last_component = &v == &path.back();

    if (ino->is_symlink() && (chase_last || !last_component)) {
      auto &link = static_cast<ISoftLink &>(*ino);
      std::string lpath = link.ReadLink();
      std::shared_ptr<IDir> newroot =
          lpath[0] == '/' ? fs.get_root() : curdir->get_this();
      ret = WalkPath(fs, std::move(newroot), split(lpath, '/'), true,
                     link_depth - 1);
      if (!ret) return MakeError(ret);
      ino = &(*ret)->get_inode_ref();
      if (ino->is_stale()) return MakeError(ESTALE);
    }

    // We hit the last inode, return it.
    if (last_component) return std::move(*ret);

    if (!ino->is_dir()) return MakeError(ENOTDIR);

    curent = std::move(*ret);
    curdir = static_cast<IDir *>(&curent->get_inode_ref());
  }

  // The last component could have been a "..".
  if (curdir->is_stale()) return MakeError(ESTALE);
  return std::move(curent);
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
  if (!f->has_dent()) return MakeError(EINVAL);
  return f->get_dent_ref().get_inode();
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
  std::shared_ptr<Inode> ino = f->get_dent_ref().get_inode();
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
  Status<std::shared_ptr<DirectoryEntry>> ret =
      WalkPath(fs, std::move(pos), spath);
  if (!ret) return MakeError(ret);
  Inode &ino = (*ret)->get_inode_ref();
  if (!ino.is_dir()) return MakeError(ENOTDIR);
  IDir &dir = static_cast<IDir &>(ino);

  if (name == "..") {
    Status<std::shared_ptr<IDir>> parent = (*ret)->get_parent_dir();
    if (unlikely(!parent)) return MakeError(parent);
    return Entry{std::move(*parent), {}, true};
  }

  if (name == ".") name = {};
  return Entry{dir.get_this(), name, must_be_dir};
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
  // mode_t type = (mode & kTypeMask);
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

Status<void> Rename(const Entry &src_entry, const Entry &dst_entry,
                    bool replace) {
  auto &[src_idir, src_name, src_must_be_dir] = src_entry;
  auto &[dst_idir, dst_name, dst_must_be_dir] = dst_entry;
  return dst_idir->Rename(*src_idir, src_name, dst_name, replace);
}

Status<void> HardLink(std::shared_ptr<Inode> src, const Entry &dst_path) {
  if (src->is_dir()) return MakeError(EPERM);
  auto &[dst_idir, dst_name, must_be_dir] = dst_path;
  if (must_be_dir) return MakeError(EPERM);
  return dst_idir->Link(dst_name, std::move(src));
}

Status<std::shared_ptr<File>> Open(const FSRoot &fs, const Entry &path,
                                   int combined_flags, mode_t mode) {
  auto &[idir, name, must_be_dir] = path;

  auto [flags, fmode] = FromFlags(combined_flags);

  // Special case for "/"
  if (!name.size()) {
    if (flags & kFlagExclusive) return MakeError(EINVAL);
    return idir->get_entry_ref().Open(flags, fmode);
  }

  Status<std::shared_ptr<DirectoryEntry>> in = idir->LookupDent(name);
  if (!in) {
    if (flags & kFlagCreate)
      return idir->Create(name, flags, mode & ~fs.get_umask(), fmode);
    return MakeError(ENOENT);
  }

  if (flags & kFlagExclusive) return MakeError(EEXIST);

  if ((*in)->get_inode_ref().is_symlink()) {
    if (!must_be_dir && (flags & (kFlagNoFollow | kFlagPath)) == kFlagNoFollow)
      return MakeError(ELOOP);
    in = WalkPath(fs, std::move(idir), {name}, true);
    if (!in) return MakeError(in);
  }

  if (flags & kFlagTruncate) (*in)->get_inode_ref().SetSize(0);
  return (*in)->Open(flags, fmode);
}

}  // namespace

Status<std::shared_ptr<DirectoryEntry>> InsertTo(const FSRoot &fs,
                                                 std::string_view path,
                                                 std::shared_ptr<Inode> ino) {
  Status<Entry> newp = LookupEntry(fs, path);
  if (!newp) return MakeError(newp);
  auto &[dst_idir, dst_name, must_be_dir] = *newp;
  if (must_be_dir) return MakeError(EINVAL);
  return dst_idir->LinkReturn(dst_name, std::move(ino));
}

// LookupDirEntry finds a dirent for a path
Status<std::shared_ptr<DirectoryEntry>> LookupDirEntry(const FSRoot &fs,
                                                       std::string_view path,
                                                       bool chase_link) {
  if (!PathIsValid(path)) return MakeError(EINVAL);
  bool must_be_dir;
  std::vector<std::string_view> spath = SplitPath(path, &must_be_dir);
  return WalkPath(fs, GetPathDir(fs, path), spath, chase_link || must_be_dir);
}

// LookupDirEntry finds a dirent for a path
Status<std::shared_ptr<DirectoryEntry>> LookupDirEntry(Process &p, int dirfd,
                                                       std::string_view path,
                                                       bool chase_link) {
  if (!PathIsValid(path)) return MakeError(EINVAL);
  Status<std::shared_ptr<IDir>> pathd = GetPathDirAt(p, dirfd, path);
  if (!pathd) return MakeError(pathd);
  bool must_be_dir;
  std::vector<std::string_view> spath = SplitPath(path, &must_be_dir);
  return WalkPath(p.get_fs(), std::move(*pathd), spath,
                  chase_link || must_be_dir);
}

// Opens a file that does nothing.
Status<std::shared_ptr<File>> ISoftLink::Open(
    uint32_t flags, FileMode fmode, std::shared_ptr<DirectoryEntry> dent) {
  assert(dent->get_inode() == Inode::get_this());
  return std::make_shared<SoftLinkFile>(flags, fmode, std::move(dent));
}

// Attempts to get the full path from the root of the filesystem to this IDir by
// traversing the chain of parents. The result is placed in @dst and an updated
// span is returned.
[[nodiscard]] Status<void> DirectoryEntry::GetFullPath(std::ostream &os) {
  // This entry is no longer valid, return the name stored in name_.
  if (!intrusive_ref_) {
    rt::SpinGuard g(lock_);
    os << name_;
    return {};
  }

  std::shared_ptr<DirectoryEntry> cur = shared_from_this();
  std::vector<std::string> paths;
  while (true) {
    auto [name, parent] = cur->get_info();
    if (unlikely(!parent)) return MakeError(ESTALE);
    // TODO - check if the parent is the root instead?
    if (parent.get() == cur.get()) break;
    paths.emplace_back(std::move(name));
    cur = std::move(parent);
  }

  for (auto it = paths.rbegin(); it != paths.rend(); it++) os << "/" << *it;
  if (paths.size() == 0) os << "/";
  return {};
}

void DirectoryEntry::RemoveFromParent() {
  for (size_t i = 0; i < 10; i++) {
    // This dirent may be moved while we are trying to unlink it.
    Status<std::shared_ptr<IDir>> parent = get_parent_dir();
    // Someone else already unlinked us.
    if (!parent) return;

    // Parent confirmed that this directory entry was removed;
    if ((*parent)->Unlink(this)) {
      assert(parent_.load().get() == nullptr);
      return;
    }
  }
  LOG(WARN) << "failed to remove dent from parent";
}

void Inode::NotifyDescriptorClosed(Process &p) {
  if (has_advisory_lock())
    AdvisoryLockMap::Get().GetCtx(this).DropLocksForPid(p.get_pid());
}

Inode::~Inode() {
  if (has_advisory_lock()) AdvisoryLockMap::Get().NotifyInodeDestroy(this);
}

//
// System call implementation
//

long usys_mknod(const char *pathname, mode_t mode, dev_t dev) {
  Status<Entry> entry = LookupEntry(myproc().get_fs(), pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = MkNod(*entry, mode, dev);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev) {
  Status<Entry> entry = LookupEntry(myproc(), dirfd, pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = MkNod(*entry, mode, dev);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_mkdir(const char *pathname, mode_t mode) {
  Status<Entry> entry = LookupEntry(myproc().get_fs(), pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = MkDir(*entry, mode);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_mkdirat(int dirfd, const char *pathname, mode_t mode) {
  Status<Entry> entry = LookupEntry(myproc(), dirfd, pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = MkDir(*entry, mode);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_unlink(const char *pathname) {
  Status<Entry> entry = LookupEntry(myproc().get_fs(), pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = Unlink(*entry);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_rmdir(const char *pathname) {
  Status<Entry> entry = LookupEntry(myproc().get_fs(), pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = RmDir(*entry);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_unlinkat(int dirfd, const char *pathname, int flags) {
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

long usys_symlink(const char *target, const char *pathname) {
  Status<Entry> entry = LookupEntry(myproc().get_fs(), pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = SymLink(*entry, target);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_symlinkat(const char *target, int dirfd, const char *pathname) {
  Status<Entry> entry = LookupEntry(myproc(), dirfd, pathname);
  if (!entry) return MakeCError(entry);
  Status<void> ret = SymLink(*entry, target);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_rename(const char *oldpath, const char *newpath) {
  FSRoot &fs = myproc().get_fs();
  Status<Entry> src_entry = LookupEntry(fs, oldpath);
  if (!src_entry) return MakeCError(src_entry);
  Status<Entry> dst_entry = LookupEntry(fs, newpath);
  if (!dst_entry) return MakeCError(dst_entry);
  Status<void> ret = Rename(*src_entry, *dst_entry, true);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_renameat(int olddirfd, const char *oldpath, int newdirfd,
                   const char *newpath) {
  Process &p = myproc();
  Status<Entry> src_entry = LookupEntry(p, olddirfd, oldpath);
  if (!src_entry) return MakeCError(src_entry);
  Status<Entry> dst_entry = LookupEntry(p, newdirfd, newpath);
  if (!dst_entry) return MakeCError(dst_entry);
  Status<void> ret = Rename(*src_entry, *dst_entry, true);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_renameat2(int olddirfd, const char *oldpath, int newdirfd,
                    const char *newpath, unsigned int flags) {
  bool replace = !(flags & RENAME_NOREPLACE);
  // TODO(amb): no flags are supported so far.
  if ((flags & ~RENAME_NOREPLACE) != 0) return -EINVAL;
  Process &p = myproc();
  Status<Entry> src_entry = LookupEntry(p, olddirfd, oldpath);
  if (!src_entry) return MakeCError(src_entry);
  Status<Entry> dst_entry = LookupEntry(p, newdirfd, newpath);
  if (!dst_entry) return MakeCError(dst_entry);
  Status<void> ret = Rename(*src_entry, *dst_entry, replace);
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
  Process &p = myproc();
  Status<Entry> entry = LookupEntry(p, dirfd, pathname);
  if (!entry) return MakeCError(entry);
  Status<std::shared_ptr<File>> f = Open(p.get_fs(), *entry, flags, mode);
  if (!f) return MakeCError(f);
  if (flags & kFlagAppend) {
    Status<off_t> ret = (*f)->Seek(0, SeekFrom::kEnd);
    if (ret) (*f)->get_off_ref() = *ret;
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
    if (ret) (*f)->get_off_ref() = *ret;
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
  Status<long> ret;
  if (p.empty()) {
    FileTable &ftbl = myproc().get_file_table();
    File *f = ftbl.Get(dirfd);
    if (unlikely(!f)) return -EBADF;
    ret = f->ReadLink(readable_span(buf, bufsiz));
  } else {
    Status<std::shared_ptr<Inode>> tmp = LookupInode(myproc(), dirfd, p, false);
    if (!tmp) return MakeCError(tmp);
    ret = DoReadLink(*tmp->get(), readable_span(buf, bufsiz));
  }

  if (!ret) return MakeCError(ret);
  return *ret;
}

ssize_t usys_readlink(const char *pathname, char *buf, size_t bufsiz) {
  std::string_view p(pathname);
  FSRoot &fs = myproc().get_fs();
  Status<std::shared_ptr<Inode>> tmp = LookupInode(fs, p, false);
  if (!tmp) return MakeCError(tmp);
  Status<long> ret = DoReadLink(*tmp->get(), readable_span(buf, bufsiz));
  if (!ret) return MakeCError(ret);
  return *ret;
}

long usys_getcwd(char *buf, size_t size) {
  FSRoot &fs = myproc().get_fs();
  rt::RuntimeLibcGuard g;
  std::ospanstream out(std::span<char>(buf, size - 1));
  Status<void> pth = fs.get_cwd_ent()->GetFullPath(out);
  if (unlikely(!pth)) return -ENOENT;
  if (unlikely(out.fail())) return -ERANGE;
  size_t sz = out.span().size();
  buf[sz] = '\0';
  return sz + 1;
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

long usys_truncate(const char *path, off_t length) {
  FSRoot &fs = myproc().get_fs();
  Status<std::shared_ptr<Inode>> tmp = LookupInode(fs, path, true);
  if (!tmp) return MakeCError(tmp);
  Inode &ino = *tmp->get();
  if (!ino.is_regular()) return -EINVAL;
  Status<void> ret = ino.SetSize(static_cast<size_t>(length));
  if (!ret) return MakeCError(ret);
  return 0;
}

long usys_chmod(const char *path, mode_t mode) {
  FSRoot &fs = myproc().get_fs();
  Status<std::shared_ptr<Inode>> ino = LookupInode(fs, path, false);
  if (!ino) return MakeCError(ino);
  (*ino)->SetMode(mode);
  return 0;
}

long usys_fchmod(int fd, mode_t mode) {
  Status<std::shared_ptr<Inode>> ino = GetFileInode(fd, myproc());
  if (!ino) return MakeCError(ino);
  (*ino)->SetMode(mode);
  return 0;
}

long usys_fchmodat(int dirfd, const char *path, mode_t mode,
                   [[maybe_unused]] int flags) {
  Status<std::shared_ptr<Inode>> ino = LookupInode(myproc(), dirfd, path);
  if (!ino) return MakeCError(ino);
  (*ino)->SetMode(mode);
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
  for (; it != s.end(); it++)
    pos = memfs::MkFolder(*pos.get(), std::string(*it));

  return Entry{std::move(pos), name, true};
}

// Mounts a memfs filesystem rooted at @pos specified by @pathname.
Status<void> MemFSMount(std::shared_ptr<IDir> pos, std::string_view mp) {
  Status<Entry> tmp = SetupMountPoint(pos, mp);
  if (!tmp) return MakeError(tmp);
  auto &[dir, name, must_be_dir] = *tmp;
  memfs::MkFolder(*dir.get(), std::string(name));
  return {};
}

// Mounts a linux fs rooted at @pos specified by @pathname from @host_path.
Status<void> LinuxFSMount(std::shared_ptr<IDir> pos,
                          std::string_view mount_point,
                          std::string_view host_path) {
  Status<Entry> tmp = SetupMountPoint(pos, mount_point);
  if (!tmp) return MakeError(tmp);
  auto &[dir, name, must_be_dir] = *tmp;
  return linuxfs::MountLinux(*dir.get(), std::string(name), host_path);
}

std::shared_ptr<DirectoryEntry> console_dent_;
std::shared_ptr<File> OpenStdio(unsigned flags, FileMode mode) {
  return std::make_shared<StdIOFile>(flags, mode, console_dent_);
}

Status<void> SetupDevices(std::shared_ptr<IDir> root) {
  std::shared_ptr<IDir> memfs = memfs::MkFolder(*root.get(), "dev");

  mode_t mode = kTypeCharacter | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
                S_IROTH | S_IWOTH;

  if (Status<void> ret = memfs->MkNod("null", mode, MakeDevice(1, 3)); !ret)
    return ret;
  if (Status<void> ret = memfs->MkNod("zero", mode, MakeDevice(1, 5)); !ret)
    return ret;
  if (Status<void> ret = memfs->MkNod("random", mode, MakeDevice(1, 8)); !ret)
    return ret;
  if (Status<void> ret = memfs->MkNod("urandom", mode, MakeDevice(1, 9)); !ret)
    return ret;
  if (Status<void> ret = memfs->MkNod("console", mode, MakeDevice(5, 1)); !ret)
    return ret;

  Status<std::shared_ptr<DirectoryEntry>> ret = memfs->LookupDent("console");
  if (!ret) panic("just added it");
  console_dent_ = std::move(*ret);

  if (Status<void> ret = memfs->SymLink("stdin", "/proc/self/fd/0"); !ret)
    return ret;
  if (Status<void> ret = memfs->SymLink("stdout", "/proc/self/fd/1"); !ret)
    return ret;
  if (Status<void> ret = memfs->SymLink("stderr", "/proc/self/fd/2"); !ret)
    return ret;

  return {};
}

[[nodiscard]] bool DirectoryEntry::WillBeSerialized() {
  return !get_inode_ref().SnapshotPrunable();
}

void DirectoryEntry::save(cereal::BinaryOutputArchive &ar) const {
  // Any inode that is getting saved will have a corresponding directory entry
  // for each link. If the parent directory is not getting saved (ie it is a
  // linux directory whose entry will be recreated prior to snapshot restore),
  // then we just save a pathname string to that entry so it can be retrieved
  // and this Entry attached at restore time. If the parent will be restored (ie
  // it is a MemIDir, etc), then we directly serialize a shared pointer
  // reference to that object and let cereal restore the connection. The
  // directory entry may also be a dangling reference to a deleted file, in
  // which case we save the empty string.
  std::shared_ptr<DirectoryEntry> p = get_parent_ent();
  bool has_serialized_parent = p && !p->get_inode_ref().SnapshotPrunable();

  if (has_serialized_parent) {
    ar(true, name_, get_inode(), get_parent_ent());
  } else {
    std::string path;
    Status<std::string> ret = const_cast<DirectoryEntry *>(this)->GetPathStr();
    if (ret) path = std::move(*ret);
    ar(false, path, get_inode());
  }
}

void DirectoryEntry::load_and_construct(
    cereal::BinaryInputArchive &ar,
    cereal::construct<DirectoryEntry> &construct) {
  bool has_parent;
  std::string name;
  std::shared_ptr<Inode> ino;
  std::shared_ptr<DirectoryEntry> parent;

  ar(has_parent, name, ino);

  if (has_parent) {
    ar(parent);
  } else if (name.size() > 0) {
    Status<Entry> entry = LookupEntry(FSRoot::GetGlobalRoot(), name);
    if (unlikely(!entry)) throw std::runtime_error("couldn't find parent");
    auto &[parentdir, ename, must_be_dir] = *entry;
    parent = parentdir->get_entry();
    name = ename;
  }

  DirectoryEntry *pe = parent.get();
  construct(std::move(name), std::move(parent), std::move(ino));

  if (pe) {
    IDir *pdir = static_cast<IDir *>(&pe->get_inode_ref());
    rt::ScopedLock g(pdir->lock_);
    pdir->InsertOverwrite(construct.ptr()->shared_from_this());
  }

  if (construct->inode_->is_dir())
    static_cast<IDir *>(construct->inode_.get())
        ->SetParent(construct.ptr()->shared_from_this());
}

Status<void> FSRestore(cereal::BinaryInputArchive &ar) {
  size_t nr_overlays;
  ar(inos);
  for (ar(nr_overlays); nr_overlays > 0; ar(nr_overlays)) {
    for (size_t i = 0; i < nr_overlays; i++) {
      std::shared_ptr<DirectoryEntry> dent;
      ar(dent);
      assert(dent.use_count() > 1);
    }
  }
  return memfs::RestoreMemFs(ar);
}

Status<void> FSSnapshot(cereal::BinaryOutputArchive &ar) {
  ar(inos);

  std::list<std::shared_ptr<DirectoryEntry>> dirq;
  dirq.push_back(FSRoot::GetGlobalRoot().get_root_ent());

  // Find directory entries that need to be saved that are contained in
  // directories that won't be retained.
  while (dirq.size() > 0) {
    std::shared_ptr<DirectoryEntry> cur = std::move(dirq.front());
    dirq.pop_front();

    if (!cur->get_inode_ref().SnapshotPrunable() &&
        cur->get_parent_dir_locked().SnapshotPrunable()) {
      GetSnapshotContext().dents.push_back(cur->shared_from_this());
    }
    if (!cur->get_inode_ref().is_dir()) continue;
    IDir &dir = static_cast<IDir &>(cur->get_inode_ref());
    if (!dir.SnapshotRecurse()) continue;
    dir.ForEach(
        [&](DirectoryEntry &ent) { dirq.push_back(ent.shared_from_this()); });
  }

  // Breadth-first tree traversal of directory entries. Each archive call
  // serializes the inode pointed to in the dent. For directories, the child
  // entries are appended to the list in the snapshot context and then handled
  // in the next iteration.
  while (GetSnapshotContext().dents.size()) {
    std::vector<std::shared_ptr<DirectoryEntry>> saves =
        std::move(GetSnapshotContext().dents);
    ar(saves.size());
    for (auto &dent : saves) ar(dent);
  }
  ar((size_t)0);

  return memfs::SaveMemFs(ar);
}

Status<void> InitFs(
    const std::vector<std::pair<std::string, std::string>> &linux_mount_points,
    const std::vector<std::string> &mem_mount_points) {
  // Set the root to the linux FS mount point.
  Status<std::shared_ptr<IDir>> tmp = linuxfs::InitLinuxRoot();
  if (!tmp) return MakeError(tmp);
  IDir &linux_root = *tmp->get();

  procfs::MakeProcFS(linux_root, "proc");
  procfs::MakeSysFS(linux_root, "sys");

  if (Status<void> ret = memfs::InitMemfs(); !ret) return ret;

  if (Status<void> ret = SetupDevices(*tmp); !ret) return ret;

  // Mount any additional linux mountpoints/filesystems.
  for (const auto &[mount_path, host_path] : linux_mount_points) {
    if (Status<void> ret = LinuxFSMount(*tmp, mount_path, host_path); !ret) {
      DLOG(WARN) << "fs: skipping mount " << mount_path << " (" << ret.error()
                 << ")";
    }
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

  std::string req_cwd = JunctionCfg::GetArg("cwd");

  // If the user didn't specify a cwd and isn't using a chroot, use the existing
  // cwd.
  if (!req_cwd.size() && GetCfg().get_chroot_path() == "/") {
    char buf[PATH_MAX];
    if (getcwd(buf, sizeof(buf)) == nullptr) return MakeError(errno);
    req_cwd = buf;
  }

  // Change the internal cwd in Junction
  if (req_cwd.size()) {
    // Get the corresponding inode.
    Status<std::shared_ptr<Inode>> ino =
        LookupInode(FSRoot::GetGlobalRoot(), req_cwd, true);
    if (!ino) return MakeError(ino);
    if (!(*ino)->is_dir()) return MakeError(ENOTDIR);
    FSRoot::GetGlobalRoot().SetCwd(
        std::static_pointer_cast<IDir>(std::move(*ino)));
  }

  return {};
}

ino_t AllocateInodeNumber() {
  static std::atomic_size_t inos;
  return inos.fetch_add(1, std::memory_order_relaxed) + 1;
}

}  // namespace junction
