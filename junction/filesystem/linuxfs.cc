extern "C" {
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
}

#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/filesystem/linuxfile.h"
#include "junction/filesystem/linuxfs.h"
#include "junction/kernel/file.h"
#include "junction/kernel/ksys.h"

namespace {

// Path where newly-created files will be written to.
const std::filesystem::path PHYS_PATH_DIR("/tmp/junction");
// Increasing counter; used to assign names to newly created files.
unsigned long fname = 0;

// Returns the next physical path to assign to a newly created/modified file.
inline std::filesystem::path next_phys_path() {
  return {PHYS_PATH_DIR / std::to_string(fname++)};
}

// Checks if a string ends with another string.
inline bool ends_with(const std::string_view& value,
                      const std::string_view& ending) {
  if (ending.size() > value.size()) return false;
  return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

inline bool starts_with(const std::string_view& value,
                        const std::string_view& starting) {
  if (starting.size() > value.size()) return false;
  return std::equal(starting.begin(), starting.end(), value.begin());
}

// Wildcard string for file paths.
const static std::string wildcard = "/*";

// Checks if the given path is a wildcard (i.e., ends with /*)
inline bool is_wildcard(const std::string_view& path) {
  return ends_with(path, wildcard);
}

// Removes the wildcard substring from the given path; returns a new
// string_view.
inline std::string_view remove_wildcard(const std::string_view& path) {
  return path.substr(0, path.size() - wildcard.size());
}

}  // namespace

namespace junction {

LinuxFileInode::LinuxFileInode(const std::string_view& name,
                               const unsigned int type)
    : Inode(type), name_(name) {}

LinuxFileInode::~LinuxFileInode() {}

std::shared_ptr<File> LinuxFileInode::Open(uint32_t mode, uint32_t flags) {
  return Open(std::to_string(fname++), mode, flags);
}

std::shared_ptr<File> LinuxFileInode::Open(const std::string_view& name,
                                           uint32_t mode, uint32_t flags) {
  std::shared_ptr<File> f = file_.lock();
  if (f) return f;
  f = LinuxFile::Open(name, flags, mode);
  file_ = f;
  return f;
}

std::shared_ptr<Inode> LinuxFileInode::Lookup(const std::string_view& name) {
  if (unlikely(type_ != kTypeDirectory)) {
    LOG(ERR) << "Cannot lookup for a non-directory inode";
    return nullptr;
  }
  for (const auto& [k, inode] : children_) {
    if (k == name) return inode;
  }
  // No matching inode found.
  return nullptr;
}

Status<void> LinuxFileInode::Insert(const std::string_view& name,
                                    std::shared_ptr<Inode> inode) {
  if (unlikely(type_ != kTypeDirectory)) {
    LOG(ERR) << "Cannot insert into a non-directory inode";
    return MakeError(EINVAL);
  }
  if (children_.find(name) != children_.end()) return MakeError(EINVAL);
  children_.insert({std::string(name), inode});
  return {};
}

Status<void> LinuxFileInode::Remove(const std::string_view& name) {
  if (unlikely(type_ != kTypeDirectory)) {
    LOG(ERR) << "Cannot remove from a non-directory inode";
    return MakeError(EINVAL);
  }
  auto it = children_.find(name);
  if (it == children_.end()) return MakeError(EINVAL);
  children_.erase(it);
  return {};
}

Status<void> LinuxFileInode::Truncate(size_t newlen) {
  return MakeError(EINVAL);
}

Status<struct stat> LinuxFileInode::Stat() { return MakeError(EINVAL); }

Status<std::shared_ptr<Inode>> LinuxFileInode::Walk(
    const std::shared_ptr<Inode> start, const std::filesystem::path target,
    const bool create_missing) {
  std::shared_ptr<Inode> cur = start;
  for (auto it = target.begin(); it != target.end(); it++) {
    // TODO(girfan): Check against current name. But be careful, same names are
    // allowed for child and parent. But we are currently creating a duplicate /
    // for /proc/self/pagemap etc. Fix that.
    std::shared_ptr<Inode> ret = cur->Lookup(it->c_str());
    if (ret) {
      cur = ret;
    } else {
      if (create_missing) {
        std::shared_ptr<LinuxFileInode> inode =
            std::make_shared<LinuxFileInode>(it->c_str(), kTypeDirectory);
        if (!cur->Insert(it->c_str(), inode)) {
          return MakeError(EINVAL);
        }
        cur = inode;
      } else {
        return MakeError(ENOENT);
      }
    }
  }
  return cur;
}

std::ostream& operator<<(std::ostream& os, const LinuxFileInode& node) {
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

std::ostream& LinuxFileInode::print(std::ostream& os,
                                    const uint32_t indent) const {
  os << std::string(indent, '\t') << name_ << " [" << type_str(type_) << "]";
  os << "\n";
  for (const auto& [k, inode] : children_) {
    std::dynamic_pointer_cast<LinuxFileInode>(inode)->print(os, indent + 1);
  }
  return os;
}

void LinuxFileSystemManifest::Insert(const std::string path,
                                     const uint32_t flags) {
  if (is_wildcard(path))
    wildcards_[std::string(remove_wildcard(path))] = flags;
  else
    files_[path] = flags;
}

void LinuxFileSystemManifest::Remove(const std::string_view path) {
  if (is_wildcard(path))
    wildcards_.erase(wildcards_.find(remove_wildcard(path)));
  else
    files_.erase(files_.find(path));
}

// TODO(girfan): Also validate the flags.
bool LinuxFileSystemManifest::Exists(const std::string_view path) const {
  if (files_.find(path) != files_.end())
    return true;
  else {
    for (const auto& it : wildcards_) {
      if (starts_with(path, it.first)) return true;
    }
  }
  return false;
}

LinuxFileSystem::LinuxFileSystem()
    : LinuxFileSystem(std::make_shared<LinuxFileSystemManifest>()) {}

LinuxFileSystem::LinuxFileSystem(
    const std::shared_ptr<const LinuxFileSystemManifest> manifest)
    : manifest_(manifest) {
  root_ = std::make_shared<LinuxFileInode>("/", kTypeDirectory);
  cwd_ = root_;
}

LinuxFileSystem::~LinuxFileSystem() {}

Status<std::shared_ptr<File>> LinuxFileSystem::Open(
    const std::string_view& pathname, uint32_t mode, uint32_t flags) {
  std::filesystem::path fp(pathname);
  std::filesystem::path fp_parent = fp.parent_path();
  std::filesystem::path name = fp.filename();
  const bool is_create = flags & kFlagCreate;
  const bool in_manifest = manifest_->Exists(pathname);
  const bool is_dir = flags & kFlagDirectory;

  // Lookup the parent directory inode.
  auto ret = LinuxFileInode::Walk(root_, fp_parent, is_create || in_manifest);
  if (!ret) return MakeError(ret);
  std::shared_ptr<Inode> pinode = *ret;

  // File associated with the inode.
  std::shared_ptr<File> f;

  // Check if the inode already exists.
  std::shared_ptr<Inode> inode = pinode->Lookup(name.c_str());
  if (inode) {
    f = std::dynamic_pointer_cast<LinuxFileInode>(inode)->Open(pathname, mode,
                                                               flags);
  } else {
    if (is_create || in_manifest) {
      // Inode does not exist; create a new one.
      inode = std::make_shared<LinuxFileInode>(
          name.c_str(), is_dir ? kTypeDirectory : kTypeRegularFile);

      // Insert the inode into its parent directory's inode.
      if (!pinode->Insert(name.c_str(), inode)) {
        LOG(ERR) << "Cannot insert inode into: " << name.c_str();
        return MakeError(EINVAL);
      }

      if (in_manifest) {
        // Create a file at the requested path.
        f = std::dynamic_pointer_cast<LinuxFileInode>(inode)->Open(pathname,
                                                                   mode, flags);
      } else {
        // Create a file at the translated path.
        f = std::dynamic_pointer_cast<LinuxFileInode>(inode)->Open(
            next_phys_path().c_str(), mode, flags);
      }
    } else {
      // The inode does not exist.
      return MakeError(ENOENT);
    }
  }

  if (!f) return MakeError(EINVAL);
  return f;
}

Status<void> LinuxFileSystem::CreateDirectory(const std::string_view& pathname,
                                              uint32_t mode) {
  // TODO(girfan): Remove after merging VFS changes
  long ret = ksys_default(reinterpret_cast<unsigned long>(pathname.data()),
                          mode, 0, 0, 0, 0, __NR_mkdir);
  if (ret) return MakeError(ret);
  return {};
}

std::ostream& operator<<(std::ostream& os, const LinuxFileSystem& fs) {
  os << "LinuxFileSystem:\n";
  os << *(std::dynamic_pointer_cast<LinuxFileInode>(fs.root_));
  return os;
}

}  // namespace junction
