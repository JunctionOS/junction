#include "syscall/handlers.hpp"

#include <errno.h>
#include <fcntl.h>
#include <syscall.h>
#include <unistd.h>

#include <csignal>
#include <filesystem>
#include <iostream>
#include <regex>
#include <string>

#include "filesystem/filesystem.hpp"

junction::FileSystem fs;

int handle_openat(int dirfd, const char* pathname, int flags, long* result) {
  if (dirfd == STDIN_FILENO || dirfd == STDOUT_FILENO ||
      dirfd == STDERR_FILENO) {
    return STATUS_FWD_TO_KERNEL;
  }

  *result = fs.openat(dirfd, pathname, flags);
  return STATUS_HANDLED;
}

int handle_open(const char* pathname, int flags, mode_t mode, long* result) {
  *result = fs.open(pathname, flags, mode);
  return STATUS_HANDLED;
}

int handle_fstat(int fd, struct stat* buf, long* result) {
  *result = fs.fstat(fd, buf);
  return STATUS_HANDLED;
}

off_t handle_lseek(int fd, off_t offset, int whence, long* result) {
  *result = fs.lseek(fd, offset, whence);
  return STATUS_HANDLED;
}

ssize_t handle_read(int fd, void* buf, size_t count, long* result) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO ||
      fd == STDERR_FILENO) {
    return STATUS_FWD_TO_KERNEL;
  }

  *result = fs.read(fd, buf, count);
  return STATUS_HANDLED;
}

ssize_t handle_write(int fd, const void* buf, size_t count, long* result) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO ||
      fd == STDERR_FILENO) {
    return STATUS_FWD_TO_KERNEL;
  }

  *result = fs.write(fd, buf, count);
  return STATUS_HANDLED;
}

int handle_close(int fd, long* result) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO ||
      fd == STDERR_FILENO) {
    return STATUS_FWD_TO_KERNEL;
  }

  *result = fs.close(fd);
  return STATUS_HANDLED;
}

int preload_file(const char* path, int flags) {
  return fs.open_fd(path, flags);
}