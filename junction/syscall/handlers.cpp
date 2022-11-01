#include "junction/syscall/handlers.hpp"

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

#include "junction/filesystem/filesystem.hpp"
#include "junction/memorysystem/memorysystem.hpp"
#include "junction/syscall/no_intercept.h"

junction::FileSystem fs;
junction::MemorySystem ms;

unsigned long handle_default(long syscall_number, long arg0, long arg1,
                             long arg2, long arg3, long arg4, long arg5) {
  return syscall_no_intercept(syscall_number, arg0, arg1, arg2, arg3, arg4,
                              arg5);
}

unsigned long handle_openat(int dirfd, const char* pathname, int flags) {
  if (dirfd == STDIN_FILENO || dirfd == STDOUT_FILENO ||
      dirfd == STDERR_FILENO) {
    return handle_default(SYS_openat, static_cast<long>(dirfd),
                          reinterpret_cast<long>(pathname),
                          static_cast<long>(flags));
  }

  return fs.openat(dirfd, pathname, flags);
}

unsigned long handle_open(const char* pathname, int flags, mode_t mode) {
  return handle_default(SYS_open, reinterpret_cast<long>(pathname),
                        static_cast<long>(flags), static_cast<long>(mode));
}

unsigned long handle_fstat(int fd, struct stat* buf) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
    return handle_default(SYS_fstat, static_cast<long>(fd),
                          reinterpret_cast<long>(buf));
  }

  return fs.fstat(fd, buf);
}

unsigned long handle_lseek(int fd, off_t offset, int whence) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
    return handle_default(SYS_lseek, static_cast<long>(fd),
                          static_cast<long>(offset), static_cast<long>(whence));
  }

  return fs.lseek(fd, offset, whence);
}

unsigned long handle_read(int fd, void* buf, size_t count) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
    return handle_default(SYS_read, static_cast<long>(fd),
                          reinterpret_cast<long>(buf),
                          static_cast<long>(count));
  }

  return fs.read(fd, buf, count);
}

unsigned long handle_write(int fd, const void* buf, size_t count) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
    return handle_default(SYS_write, static_cast<long>(fd),
                          reinterpret_cast<long>(buf),
                          static_cast<long>(count));
  }

  return fs.write(fd, buf, count);
}

unsigned long handle_close(int fd) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
    return handle_default(SYS_close, static_cast<long>(fd));
  }

  return fs.close(fd);
}

unsigned long handle_mmap(void* addr, size_t length, int prot, int flags,
                          int fd, off_t offset) {
  if ((flags & MAP_ANONYMOUS) == MAP_ANONYMOUS) {
    return handle_default(SYS_mmap, reinterpret_cast<long>(addr),
                          static_cast<long>(length), static_cast<long>(prot),
                          static_cast<long>(flags), static_cast<long>(fd),
                          static_cast<long>(offset));
  }

  auto file = fs.get_file(fd);
  if (!file.has_value()) {
    // TODO(girfan): This needs to be errored out.
    return handle_default(SYS_mmap, reinterpret_cast<long>(addr),
                          static_cast<long>(length), static_cast<long>(prot),
                          static_cast<long>(flags), static_cast<long>(fd),
                          static_cast<long>(offset));
  }

  void* map = ms.mmap(addr, length, prot, flags, file->get(), offset);
  return reinterpret_cast<long>(map);
}

unsigned long handle_munmap(void* addr, size_t length) {
  auto status = ms.munmap(addr, length);
  if (status == 1) {
    // This indicates that the address was not mapped using the MemorySystem.
    return handle_default(SYS_munmap, reinterpret_cast<long>(addr),
                          static_cast<long>(length));
  }

  return status;
}

int preload_file(const char* path, int flags) {
  return fs.open_fd(path, flags);
}
