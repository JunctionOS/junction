// memfs.h - in-memory filesystem

#pragma once

extern "C" {
#include <sys/stat.h>
#include <time.h>
}

#include <atomic>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "junction/base/containers.h"
#include "junction/base/error.h"
#include "junction/base/slab_list.h"
#include "junction/kernel/file.h"
#include "junction/kernel/fs.h"

namespace junction {

class MemFSInode : public Inode,
                   public std::enable_shared_from_this<MemFSInode> {
  constexpr static size_t kMaxSizeBytes = (1UL << 33);  // 8 GB
  constexpr static size_t kBlockSize = 4096;            // 4KB (page size)

 public:
  MemFSInode(const unsigned int type) noexcept;
  ~MemFSInode() override = default;

  virtual std::shared_ptr<File> Open(const std::string_view &name,
                                     uint32_t mode, uint32_t flags);
  virtual std::shared_ptr<File> Open(uint32_t mode, uint32_t flags) override;
  virtual std::shared_ptr<Inode> Lookup(const std::string_view &name) override;
  virtual Status<void> Insert(const std::string_view &name,
                              std::shared_ptr<Inode> inode) override;
  virtual Status<void> Remove(const std::string_view &name) override;
  virtual Status<void> Truncate(off_t newlen) override;
  virtual Status<void> Allocate(int mode, off_t offset, off_t len) override;
  virtual Status<void> Stat(struct stat *buf) override;
  virtual Status<size_t> Read(std::span<std::byte> buf, off_t off) override;
  virtual Status<size_t> Write(std::span<const std::byte> buf,
                               off_t off) override;

  Status<int> GetDents(void *dirp, unsigned int *count, off_t *off);
  Status<bool> IsEmpty();

  friend std::ostream &operator<<(std::ostream &os, const MemFSInode &node);

 private:
  // inode number to assign to the next inode
  static std::atomic<unsigned int> next_inum;

  // child nodes (in the case of directory type inode)
  string_unordered_map<std::shared_ptr<Inode>> children_;
  // contents (in the case of a regular file type inode)
  SlabList<kBlockSize> buf_;

  // number of hard links
  unsigned int nlink_;
  // time of last access
  time_t atime_;
  // time of last modification
  time_t mtime_;
  // time of last status change
  time_t ctime_;

  std::ostream &print(std::ostream &os, const uint32_t indent = 0) const;

  friend class MemFS;
};

class MemFS : public FileSystem {
 public:
  MemFS() noexcept;
  MemFS(std::vector<std::string> prefixes) noexcept;
  MemFS(const std::string_view &pathname) noexcept;
  ~MemFS() override = default;
  virtual Status<std::shared_ptr<File>> Open(const std::string_view &pathname,
                                             uint32_t mode,
                                             uint32_t flags) override;
  virtual Status<void> CreateDirectory(const std::string_view &pathname,
                                       uint32_t mode) override;
  virtual Status<void> RemoveDirectory(
      const std::string_view &pathname) override;
  virtual Status<void> StatFS(const std::string_view &pathname,
                              struct statfs *buf) override;
  virtual Status<void> Stat(const std::string_view &pathname,
                            struct stat *buf) override;
  virtual Status<void> Link(const std::string_view &oldpath,
                            const std::string_view &newpath) override;
  virtual Status<void> Unlink(const std::string_view &pathname) override;
  virtual bool is_supported(const std::string_view &pathname, uint32_t mode,
                            uint32_t flags) override;

  // Lookup and return the inode for a given path.
  Status<std::shared_ptr<Inode>> GetInode(const std::string_view &pathname);
  Status<std::shared_ptr<Inode>> GetInode(
      const std::filesystem::path &pathname);
  // Lookup and return the parent inode for a given path.
  Status<std::shared_ptr<Inode>> GetParentInode(
      const std::string_view &pathname);
  Status<std::shared_ptr<Inode>> GetParentInode(
      const std::filesystem::path &pathname);

 private:
  const std::vector<std::string> prefixes_;
  std::shared_ptr<MemFSInode> root_;
  std::shared_ptr<MemFSInode> cwd_;

  friend std::ostream &operator<<(std::ostream &os, const MemFS &fs);
};

}  // namespace junction
