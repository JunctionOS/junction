#pragma once

#include <sys/stat.h>
#include <sys/types.h>

#include <string>
#include <unordered_map>
#include <optional>
#include <functional>

#include "filesystem/file.hpp"

namespace junction {

class FileSystem {
public:
  FileSystem();
  ~FileSystem() = default;

  /* disallow copy */
  FileSystem(const FileSystem& temp_obj) = delete;
  FileSystem& operator=(const FileSystem& temp_obj) = delete;

  int openat(int dirfd, const char* pathname, int flags);
  int open(const char* pathname, int flags, mode_t mode);
  int fstat(int fd, struct stat* buf);
  off_t lseek(int fd, off_t offset, int whence);
  ssize_t read(int fd, void* buf, size_t count);
  ssize_t write(int fd, const void* buf, size_t count);
  int close(int fd);

  int open_fd(const char* path, int flags);
  std::optional<std::reference_wrapper<const File>> get_file(
    const int fd) const;

private:
  std::unordered_map<std::string, int> _path_to_fd;
  std::unordered_map<int, File> _fd_to_file;
};

} // namespace junction