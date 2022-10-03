#include "syscall/handlers.hpp"

#include <errno.h>
#include <fcntl.h>
#include <syscall.h>

#include <csignal>
#include <filesystem>
#include <iostream>
#include <regex>
#include <string>

#include "filesystem/filesystem.hpp"

junction::FileSystem fs;

int handle_openat(int dirfd, const char* pathname, int flags) {
  return fs.openat(dirfd, pathname, flags);
}

int handle_open(const char* pathname, int flags, mode_t mode) {
  return fs.open(pathname, flags, mode);
}

int handle_fstat(int fd, struct stat* buf) { return fs.fstat(fd, buf); }

off_t handle_lseek(int fd, off_t offset, int whence) {
  return fs.lseek(fd, offset, whence);
}

ssize_t handle_read(int fd, void* buf, size_t count) {
  return fs.read(fd, buf, count);
}

ssize_t handle_write(int fd, const void* buf, size_t count) {
  return fs.write(fd, buf, count);
}

int handle_close(int fd) { return fs.close(fd); }

int preload_file(const char* path, int flags) {
  return fs.open_fd(path, flags);
}