#include "syscall/handlers.hpp"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>

#include <csignal>
#include <filesystem>
#include <iostream>
#include <regex>
#include <string>

#include "filesystem/filesystem.hpp"
#include "memorysystem/memorysystem.hpp"
#include "spdlog/spdlog.h"

junction::FileSystem fs;
junction::MemorySystem ms;

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
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
    return STATUS_FWD_TO_KERNEL;
  }

  *result = fs.fstat(fd, buf);
  return STATUS_HANDLED;
}

int handle_lseek(int fd, off_t offset, int whence, long* result) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
    return STATUS_FWD_TO_KERNEL;
  }

  auto ret = fs.lseek(fd, offset, whence);
  *result = static_cast<long>(ret);
  return STATUS_HANDLED;
}

int handle_read(int fd, void* buf, size_t count, long* result) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
    return STATUS_FWD_TO_KERNEL;
  }

  auto ret = fs.read(fd, buf, count);
  *result = static_cast<long>(ret);
  return STATUS_HANDLED;
}

int handle_write(int fd, const void* buf, size_t count, long* result) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
    return STATUS_FWD_TO_KERNEL;
  }

  auto ret = fs.write(fd, buf, count);
  *result = static_cast<long>(ret);
  return STATUS_HANDLED;
}

int handle_close(int fd, long* result) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
    return STATUS_FWD_TO_KERNEL;
  }

  *result = fs.close(fd);
  return STATUS_HANDLED;
}

int handle_mmap(void* addr, size_t length, int prot, int flags, int fd,
                off_t offset, long* result) {
  if ((flags & MAP_ANONYMOUS) == MAP_ANONYMOUS) {
    return STATUS_FWD_TO_KERNEL;
  }

  auto file = fs.get_file(fd);
  if (!file.has_value()) {
    *result = reinterpret_cast<long>(MAP_FAILED);
    return STATUS_HANDLED;
  }

  void* map = ms.mmap(addr, length, prot, flags, file->get(), offset);
  *result = reinterpret_cast<long>(map);
  return STATUS_HANDLED;
}

int handle_munmap(void* addr, size_t length, long* result) {
  int status = ms.munmap(addr, length);
  if (status == 1) {
    // This indicates that the address was not mapped using the MemorySystem.
    return STATUS_FWD_TO_KERNEL;
  }

  *result = status;
  return STATUS_HANDLED;
}

int preload_file(const char* path, int flags) {
  return fs.open_fd(path, flags);
}
