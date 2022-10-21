#include "jnct/filesystem/filesystem.hpp"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syscall.h>

#include <csignal>
#include <filesystem>
#include <functional>
#include <iostream>
#include <optional>
#include <regex>
#include <string>

#include "jnct/filesystem/file.hpp"
#include "spdlog/spdlog.h"

namespace junction {

FileSystem::FileSystem() { spdlog::set_level(spdlog::level::trace); }

std::optional<std::reference_wrapper<const File>> FileSystem::get_file(
    const int fd) const {
  const auto file_iter = _fd_to_file.find(fd);
  if (file_iter == _fd_to_file.end()) {
    return std::nullopt;
  }

  return file_iter->second;
}

int FileSystem::openat(int dirfd, const char* pathname, int flags) {
  if (dirfd != AT_FDCWD) {
    spdlog::warn("Cannot openat; unsupported dirfd: {0}", dirfd);
    return -1;
  }

  const std::string pathname_str(pathname);
  const auto fd_iter = _path_to_fd.find(pathname_str);
  if (fd_iter == _path_to_fd.end()) {
    spdlog::debug("Cannot openat; fd not found: {0}", pathname_str);
    return -1;
  }

  const int fd = fd_iter->second;
  const auto file_iter = _fd_to_file.find(fd);
  if (file_iter == _fd_to_file.end()) {
    spdlog::debug("Cannot openat; file not found: {0}", fd);
    return -1;
  }

  return file_iter->second.openat();
}

int FileSystem::open(const char* pathname, int flags, mode_t mode) {
  std::cerr << "Unspported operation: open" << std::endl;
  return -1;
}

int FileSystem::fstat(int fd, struct stat* buf) {
  const auto file_iter = _fd_to_file.find(fd);
  if (file_iter == _fd_to_file.end()) {
    std::cerr << "Cannot fstat; file not found: " << fd << std::endl;
    return -1;
  }

  return file_iter->second.fstat(buf);
}

off_t FileSystem::lseek(int fd, off_t offset, int whence) {
  const auto file_iter = _fd_to_file.find(fd);
  if (file_iter == _fd_to_file.end()) {
    std::cerr << "Cannot lseek; file not found: " << fd << std::endl;
    return -1;
  }

  return file_iter->second.lseek(offset, whence);
}

ssize_t FileSystem::read(int fd, void* buf, size_t count) {
  const auto file_iter = _fd_to_file.find(fd);
  if (file_iter == _fd_to_file.end()) {
    std::cerr << "Cannot read; file not found: " << fd << std::endl;
    return -1;
  }

  return file_iter->second.read(buf, count);
}

ssize_t FileSystem::write(int fd, const void* buf, size_t count) {
  const auto file_iter = _fd_to_file.find(fd);
  if (file_iter == _fd_to_file.end()) {
    std::cerr << "Cannot write; file not found: " << fd << std::endl;
    return -1;
  }

  return file_iter->second.write(buf, count);
}

int FileSystem::close(int fd) {
  const auto file_iter = _fd_to_file.find(fd);
  if (file_iter == _fd_to_file.end()) {
    std::cerr << "Cannot close; file not found: " << fd << std::endl;
    return -1;
  }

  return file_iter->second.close();
}

int FileSystem::open_fd(const char* path, int flags) {
  int ret = -1;
  const std::string path_str(path);

  // Check if the path was already opened and there is an associated fd.
  const auto fd_iter = _path_to_fd.find(path_str);
  if (fd_iter == _path_to_fd.end()) {
    // Get an fd for this path.
    int fd = ::open(path, flags);
    if (fd >= 0) {
      // Create a mapping between the path to the fd.
      _path_to_fd[path_str] = fd;
      // TODO(gohar): Temp, we should have a separte Dir class.
      bool is_dir = (flags & O_DIRECTORY) == O_DIRECTORY;
      // Create a mapping between the fd and File.
      _fd_to_file.emplace(std::piecewise_construct, std::forward_as_tuple(fd),
                          std::forward_as_tuple(fd, path_str, is_dir));
      std::cout << "Opened: " << path_str << " (" << fd << ")" << std::endl;
      ret = 0;
    } else {
      std::cerr << "Cannot open: " << path << std::endl;
      perror("open");
    }
  } else {
    // Already opened.
    ret = 0;
  }

  return ret;
}

}  // namespace junction
