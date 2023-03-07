extern "C" {
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
}

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>

#include "junction/base/error.h"
#include "junction/base/string.h"
#include "junction/bindings/log.h"
#include "junction/filesystem/memfs.h"
#include "junction/filesystem/memfsfile.h"
#include "junction/kernel/file.h"

namespace {

static const std::string STR_DIR("DIR");
static const std::string STR_FILE("FILE");
static const std::string STR_UNKNOWN("UNKNOWN");

// Source: https://man7.org/linux/man-pages/man2/statfs.2.html
static const __fsword_t TMPFS_MAGIC = 0x01021994;

struct linux_dirent {
  unsigned long d_ino;
  unsigned long d_off;
  unsigned short d_reclen;
  char d_name[];
};

std::vector<std::string> GetFileList(const std::string_view& pathname) {
  std::vector<std::string> paths;
  if (pathname.empty()) return paths;

  std::ifstream f(pathname.data());
  std::string line;
  while (std::getline(f, line)) {
    paths.emplace_back(line);
  }
  return paths;
}

}  // namespace

namespace junction {

std::atomic<unsigned int> MemFSInode::next_inum{0};

MemFSInode::MemFSInode(const unsigned int type) noexcept
    : Inode(type,
            MemFSInode::next_inum.fetch_add(1, std::memory_order_relaxed)) {
  nlink_ = 0;
  atime_ = time(nullptr);
  mtime_ = atime_;
  ctime_ = atime_;
}

std::shared_ptr<File> MemFSInode::Open(const std::string_view& name,
                                       uint32_t mode, uint32_t flags) {
  auto ret = MemFSFile::Open(name, flags, mode, shared_from_this());
  if (unlikely(!ret)) return nullptr;
  return ret;
}

std::shared_ptr<File> MemFSInode::Open(uint32_t mode, uint32_t flags) {
  return Open("", mode, flags);
}

std::shared_ptr<Inode> MemFSInode::Lookup(const std::string_view& name) {
  if (unlikely(type_ != kTypeDirectory)) return nullptr;

  for (const auto& [k, inode] : children_) {
    if (k == name) return inode;
  }
  return nullptr;
}

Status<void> MemFSInode::Insert(const std::string_view& name,
                                std::shared_ptr<Inode> inode) {
  if (unlikely(type_ != kTypeDirectory)) return MakeError(EINVAL);

  std::shared_ptr<MemFSInode> mfsinode =
      std::dynamic_pointer_cast<MemFSInode>(inode);

  if (unlikely(children_.find(name) != children_.end()))
    return MakeError(EINVAL);
  children_.insert({std::string(name), inode});
  mfsinode->nlink_++;
  return {};
}

Status<void> MemFSInode::Remove(const std::string_view& name) {
  if (unlikely(type_ != kTypeDirectory)) return MakeError(EINVAL);

  auto it = children_.find(name);
  if (unlikely(it == children_.end())) return MakeError(EINVAL);

  std::shared_ptr<MemFSInode> mfsinode =
      std::dynamic_pointer_cast<MemFSInode>(it->second);

  mfsinode->nlink_--;
  children_.erase(it);
  return {};
}

Status<void> MemFSInode::Truncate(off_t newlen) {
  if (unlikely(newlen > kMaxSizeBytes)) return MakeError(EINVAL);
  if (unlikely(type_ == kTypeDirectory)) return MakeError(EISDIR);

  buf_.Resize(newlen);
  mtime_ = time(nullptr);
  ctime_ = mtime_;
  return {};
}

Status<void> MemFSInode::Allocate(int mode, off_t offset, off_t len) {
  if (mode & FALLOC_FL_UNSHARE_RANGE) return MakeError(EOPNOTSUPP);

  if (mode == 0) {
    const size_t newlen = offset + len;
    if (newlen > buf_.size()) {
      if (mode & FALLOC_FL_KEEP_SIZE) return MakeError(EOPNOTSUPP);
      if (unlikely(newlen > kMaxSizeBytes)) return MakeError(EINVAL);
      buf_.Resize(newlen);
    }
  } else if (mode == (FALLOC_FL_PUNCH_HOLE & FALLOC_FL_KEEP_SIZE)) {
    std::fill_n(buf_.begin() + offset, len, std::byte{0});
  } else if (mode == FALLOC_FL_COLLAPSE_RANGE) {
    // TODO(girfan): Need to add Erase() to SlabList
    // buf_.erase(buf_.begin() + offset, buf_.begin() + offset + len);
    LOG(WARN) << "Unsupported operation: FALLOC_FL_COLLAPSE_RANGE";
  } else if (mode & FALLOC_FL_ZERO_RANGE) {
    const size_t newlen = offset + len;
    if (newlen > buf_.size()) {
      if (mode & FALLOC_FL_KEEP_SIZE) return MakeError(EOPNOTSUPP);
      buf_.Resize(newlen);
    }
    std::fill_n(buf_.begin() + offset, len, std::byte{0});
  } else if (mode == FALLOC_FL_INSERT_RANGE) {
    buf_.Resize(len + buf_.size());
    // TODO(girfan): This may be buggy!
    LOG(WARN) << "Unsupported operation: FALLOC_FL_INSERT_RANGE";
    // std::shift_right(buf_.begin() + offset, buf_.begin() + offset + len,
    // len);
  } else {
    return MakeError(EINVAL);
  }
  mtime_ = time(nullptr);
  ctime_ = mtime_;
  return {};
}

Status<void> MemFSInode::Stat(struct stat* buf) {
  buf->st_dev = 0;
  buf->st_ino = ino_;
  buf->st_mode = get_type();
  buf->st_nlink = nlink_;
  buf->st_uid = 0;
  buf->st_gid = 0;
  buf->st_rdev = 0;
  buf->st_size = buf_.size();
  buf->st_blksize = sysconf(_SC_PAGESIZE);
  buf->st_blocks = 0;
  buf->st_atime = atime_;
  buf->st_mtime = mtime_;
  buf->st_ctime = ctime_;
  return {};
}

Status<size_t> MemFSInode::Read(std::span<std::byte> buf, off_t off) {
  const size_t n = std::min(buf.size(), buf_.size() - off);
  std::copy_n(buf_.cbegin() + off, n, buf.begin());
  return n;
}

Status<size_t> MemFSInode::Write(std::span<const std::byte> buf, off_t off) {
  if (buf_.size() - off < buf.size()) {
    buf_.Resize(buf.size() + off);
  }
  std::copy_n(buf.begin(), buf.size(), buf_.begin() + off);
  return buf.size();
}

Status<int> MemFSInode::GetDents(void* dirp, unsigned int* count, off_t* off) {
  if (unlikely(type_ != kTypeDirectory)) return MakeError(EINVAL);
  if ((size_t)*off >= children_.size()) return 0;

  auto it = children_.cbegin();
  std::advance(it, *off);
  unsigned int read_bytes = 0;

  for (; it != children_.cend(); it++) {
    const auto& name = it->first;
    const auto& inode = it->second;

    size_t reclen = AlignUp(
        offsetof(struct linux_dirent, d_name) + name.size() + 2, sizeof(long));
    if (reclen > (*count - read_bytes)) return read_bytes;

    struct linux_dirent* dent = reinterpret_cast<struct linux_dirent*>(dirp);
    std::strcpy(dent->d_name, name.c_str());
    dent->d_ino = inode->get_ino();
    *(reinterpret_cast<char*>(dent) + reclen - 1) =
        inode->get_type() == kTypeDirectory ? DT_DIR : DT_REG;
    dent->d_reclen = reclen;
    dent->d_off = *off;

    *off += 1;
    read_bytes += reclen;
    dirp = reinterpret_cast<char*>(dent) + reclen;
  }

  return read_bytes;
}

Status<bool> MemFSInode::IsEmpty() {
  if (unlikely(type_ != kTypeDirectory)) return MakeError(ENOTDIR);
  return children_.empty();
}

std::ostream& operator<<(std::ostream& os, const MemFSInode& node) {
  return node.print(os);
}

inline std::string type_str(const uint32_t type) {
  if (type == kTypeDirectory)
    return std::move("Dir");
  else if (type == kTypeRegularFile)
    return std::move("File");
  else
    return std::move("Unknown");
}

std::ostream& MemFSInode::print(std::ostream& os, const uint32_t indent) const {
  for (const auto& [k, inode] : children_) {
    os << std::string(indent, '\t') << k << " [" << type_str(type_) << "]";
    os << "\n";
    std::dynamic_pointer_cast<MemFSInode>(inode)->print(os, indent + 1);
  }
  return os;
}

MemFS::MemFS() noexcept : MemFS::MemFS(std::vector<std::string>({"/memfs"})) {}

MemFS::MemFS(const std::string_view& pathname) noexcept
    : MemFS::MemFS(std::move(GetFileList(pathname))) {}

MemFS::MemFS(std::vector<std::string> prefixes) noexcept
    : prefixes_(std::move(prefixes)) {
  root_ = std::make_shared<MemFSInode>(kTypeDirectory);
  root_->nlink_++;
  cwd_ = root_;
  // Create inodes for all valid prefixes that this file system supports.
  for (const auto& prefix : prefixes_) {
    std::shared_ptr<Inode> cur = root_;
    const std::filesystem::path fp(prefix);
    if (!fp.is_absolute()) {
      LOG(WARN) << "Prefixes must be absolute paths, ignoring: " << fp;
      continue;
    }
    // Skip the root node, we already have that.
    for (auto it = ++fp.begin(); it != fp.end(); it++) {
      // Check if this directory already exists.
      std::shared_ptr<Inode> inode = cur->Lookup((*it).c_str());
      if (!inode) {
        // Directory does not exist; create and insert.
        inode = std::make_shared<MemFSInode>(kTypeDirectory);
        if (!cur->Insert((*it).c_str(), inode)) {
          LOG(ERR) << "Cannot insert inode for: " << *it << " (" << fp << ")";
          break;
        }
      }
      cur = inode;
    }
  }
  LOG(DEBUG) << *this;
}

Status<std::shared_ptr<File>> MemFS::Open(const std::string_view& pathname,
                                          uint32_t mode, uint32_t flags) {
  const std::filesystem::path fp(pathname);
  const bool is_create = flags & kFlagCreate;
  const bool is_dir = flags & kFlagDirectory;

  // Get the parent inode.
  auto ret = GetParentInode(fp);
  if (unlikely(!ret)) return MakeError(ret);
  std::shared_ptr<Inode> parent = *ret;

  // Lookup the path inside the parent.
  std::shared_ptr<Inode> child = parent->Lookup(fp.filename().c_str());

  if (!child) {
    if (!is_create) return MakeError(ENOENT);
    // Create a new inode for this path and insert it into the parent.
    child = std::make_shared<MemFSInode>(is_dir ? kTypeDirectory
                                                : kTypeRegularFile);
    auto ins = parent->Insert(fp.filename().c_str(), child);
    if (unlikely(!ins)) return MakeError(ins);
  }

  // Open a new file in the inode.
  auto f = child->Open(mode, flags);
  if (unlikely(!f)) return MakeError(EINVAL);
  return f;
}

bool MemFS::is_supported(const std::string_view& pathname,
                         [[maybe_unused]] uint32_t mode, uint32_t flags) {
  // The path already exists.
  if (GetInode(pathname)) return true;
  // The path may be created and the parent exists.
  if ((flags & kFlagCreate) && GetParentInode(pathname)) return true;
  // The path does not exist and cannot be created.
  return false;
}

Status<std::shared_ptr<Inode>> MemFS::GetInode(
    const std::string_view& pathname) {
  return GetInode(std::filesystem::path(pathname));
}

Status<std::shared_ptr<Inode>> MemFS::GetInode(
    const std::filesystem::path& pathname) {
  // TODO(girfan): Use a fixed-size LRU cache to avoid walking the tree?
  auto it = pathname.begin();
  if (unlikely(it == pathname.end())) return MakeError(ENOENT);

  // Determine the starting inode for traversal.
  std::shared_ptr<Inode> cur;
  if (pathname.is_relative()) {
    cur = cwd_;
  } else {
    // In this case, the first element of the path (i.e., root "/") will be
    // skipped; we are already at the root and need to start looking under it.
    cur = root_;
    it++;
  }

  for (; it != pathname.end(); it++) {
    const std::shared_ptr<Inode> ret = cur->Lookup(it->c_str());
    if (unlikely(!ret)) return MakeError(ENOENT);
    cur = ret;
  }
  return cur;
}

Status<std::shared_ptr<Inode>> MemFS::GetParentInode(
    const std::string_view& pathname) {
  return GetParentInode(std::filesystem::path(pathname));
}

Status<std::shared_ptr<Inode>> MemFS::GetParentInode(
    const std::filesystem::path& pathname) {
  return GetInode(pathname.parent_path());
}

Status<void> MemFS::CreateDirectory(const std::string_view& pathname,
                                    uint32_t mode) {
  const std::filesystem::path fp(pathname);

  // Get the parent inode.
  auto ret = GetParentInode(fp);
  if (unlikely(!ret)) return MakeError(ret);
  std::shared_ptr<Inode> parent = *ret;

  // Lookup the path inside the parent.
  std::shared_ptr<Inode> child = parent->Lookup(fp.filename().c_str());
  if (unlikely(child)) return MakeError(EEXIST);

  // Create a new inode for this path and insert it into the parent.
  child = std::make_shared<MemFSInode>(kTypeDirectory);
  auto ins = parent->Insert(fp.filename().c_str(), child);
  if (unlikely(!ins)) return MakeError(ins);

  return {};
}

Status<void> MemFS::RemoveDirectory(const std::string_view& pathname) {
  const std::filesystem::path fp(pathname);

  auto ret = GetParentInode(fp);
  if (unlikely(!ret)) return MakeError(ret);
  std::shared_ptr<Inode> parent = *ret;

  // Lookup the path inside the parent.
  std::shared_ptr<MemFSInode> inode = std::dynamic_pointer_cast<MemFSInode>(
      parent->Lookup(fp.filename().c_str()));
  if (unlikely(!inode)) return MakeError(ENOENT);
  if (unlikely(inode->get_type() != kTypeDirectory)) return MakeError(ENOTDIR);
  if (unlikely(!inode->IsEmpty())) return MakeError(ENOTEMPTY);
  if (unlikely(inode->nlink_ > 0)) {
    // Ref: https://elixir.bootlin.com/linux/v5.13/source/fs/ext4/namei.c#L3280
    //
    // TODO(girfan): Leave dangling pointers to this inode from other inodes
    // that may have created links to this? This will leak memory and not clean
    // up the MemFSInode because some other MemFSInode is holding a shared_ptr
    // to this in their children_ data structure.
    LOG(WARN) << "Empty directory has too many links: " << inode->nlink_;
  }

  auto rem = parent->Remove(fp.filename().c_str());
  if (unlikely(!rem)) return MakeError(rem);
  return {};
}

Status<void> MemFS::StatFS(const std::string_view& pathname,
                           struct statfs* buf) {
  buf->f_type = TMPFS_MAGIC;
  buf->f_bsize = sysconf(_SC_PAGESIZE);
  buf->f_namelen = 255;
  return {};
}

Status<void> MemFS::Stat(const std::string_view& pathname, struct stat* buf) {
  const std::filesystem::path fp(pathname);
  auto ret = GetInode(fp);
  if (unlikely(!ret)) return MakeError(ret);
  return (*ret)->Stat(buf);
}

Status<void> MemFS::Link(const std::string_view& oldpath,
                         const std::string_view& newpath) {
  const std::filesystem::path oldfp(oldpath);
  const std::filesystem::path newfp(newpath);

  auto ret = GetInode(newfp);
  if (unlikely(ret)) return MakeError(EEXIST);

  ret = GetParentInode(newfp);
  if (unlikely(!ret)) return MakeError(ENOENT);
  std::shared_ptr<Inode> newparent = *ret;

  ret = GetInode(oldfp);
  if (unlikely(!ret)) return MakeError(ENOENT);
  std::shared_ptr<Inode> old = *ret;

  // Insert will increment nlink_ for the old inode.
  auto ins = newparent->Insert(newfp.filename().c_str(), old);
  if (unlikely(!ins)) return MakeError(ins);
  return {};
}

Status<void> MemFS::Unlink(const std::string_view& pathname) {
  const std::filesystem::path fp(pathname);

  auto ret = GetParentInode(fp);
  if (unlikely(!ret)) return MakeError(ENOENT);
  std::shared_ptr<Inode> parent = *ret;

  // Lookup the path inside the parent.
  std::shared_ptr<MemFSInode> child = std::dynamic_pointer_cast<MemFSInode>(
      parent->Lookup(fp.filename().c_str()));
  if (unlikely(!child)) return MakeError(ENOENT);

  // Note: nlink_ is not dictating when the memory for MemFSInode being unlinked
  // will be freed; that is determined by when there are no more shared_ptrs in
  // any other MemFSInode's children_ data structure which will lead to the
  // destruction of the inode being unlinked. nlink_ is only for supporting ops
  // like Stat.
  // Remove will decrement nlink_ for the inode.
  assert(child->nlink_ > 0);
  return parent->Remove(fp.filename().c_str());
}

std::ostream& operator<<(std::ostream& os, const MemFS& fs) {
  os << "MemFS:\n";
  os << *(std::dynamic_pointer_cast<MemFSInode>(fs.root_));
  return os;
}

}  // namespace junction
