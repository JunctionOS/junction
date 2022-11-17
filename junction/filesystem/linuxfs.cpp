extern "C" {
#include <sys/stat.h>
}

#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/filesystem/linuxfile.hpp"
#include "junction/filesystem/linuxfs.hpp"
#include "junction/kernel/file.h"

namespace junction {

// TODO(girfan): This implementation is NOT thread-safe. That will be fixed
// soon.

LinuxFileInode::LinuxFileInode(const std::string_view& name,
                               const unsigned int type)
    : Inode(type), name_(name) {}

LinuxFileInode::~LinuxFileInode() {}

std::shared_ptr<File> LinuxFileInode::Open(uint32_t mode, uint32_t flags) {
  if (unlikely(type_ != kTypeRegularFile)) {
    LOG(ERR) << "Cannot open file for a non-file inode";
    return nullptr;
  }
  // TODO(girfan): Use a random indentifier for the file.
  return Open("", mode, flags);
}

std::shared_ptr<File> LinuxFileInode::Open(const std::string_view& name,
                                           uint32_t mode, uint32_t flags) {
  if (unlikely(type_ != kTypeRegularFile)) {
    LOG(ERR) << "Cannot open file for a non-file inode";
    return nullptr;
  }
  std::shared_ptr<LinuxFile> file =
      std::make_shared<LinuxFile>(name, flags, mode);
  files_.insert(file);
  return file;
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

std::ostream& operator<<(std::ostream& os, const LinuxFileInode& node) {
  return node.print(os);
}

inline std::string type_str(const uint32_t type) {
  if (type == kTypeDirectory) {
    return std::move("Dir");
  } else if (type == kTypeRegularFile) {
    return std::move("File");
  } else {
    return std::move("Unknown");
  }
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

LinuxFileSystem::LinuxFileSystem() {
  root_ = std::make_shared<LinuxFileInode>("/", kTypeDirectory);
  cwd_ = root_;
}

LinuxFileSystem::~LinuxFileSystem() {}

Status<std::shared_ptr<File>> LinuxFileSystem::Open(const std::string_view& pathname,
                                            uint32_t mode, uint32_t flags) {
  // TODO(girfan): Check the manifest and create a virtual-physical mapping.
  std::filesystem::path fp(pathname);
  std::filesystem::path fp_parent = fp.parent_path();
  std::filesystem::path name = fp.filename();

  // Lookup the parent directory inode.
  std::shared_ptr<Inode> dir = cwd_;
  for (auto it = fp_parent.begin(); it != fp_parent.end(); it++) {
    std::shared_ptr<Inode> ret = dir->Lookup(it->c_str());
    if (!ret) {
      auto inode =
          std::make_shared<LinuxFileInode>(it->c_str(), kTypeDirectory);
      if (!dir->Insert(it->c_str(), inode)) {
        LOG(ERR) << "Cannot insert directory inode into: " << it->c_str();
        return MakeError(EINVAL);
      }
      dir = inode;
    } else {
      dir = ret;
    }
  }

  // Create a new inode for the file being opened.
  std::shared_ptr<LinuxFileInode> inode =
      std::make_shared<LinuxFileInode>(name.c_str(), kTypeRegularFile);

  // Insert the file inode into the parent directory inode.
  if (!dir->Insert(name.c_str(), inode)) {
    LOG(ERR) << "Cannot insert file inode into: " << name.c_str();
    return MakeError(EINVAL);
  }

  // Open the file into the directory inode.
  return inode->Open(pathname, mode, flags);
}

std::ostream& operator<<(std::ostream& os, const LinuxFileSystem& fs) {
  os << "LinuxFileSystem:\n";
  os << *(std::dynamic_pointer_cast<LinuxFileInode>(fs.root_));
  return os;
}

}  // namespace junction
