extern "C" {
#include <sys/stat.h>
#include <syscall.h>
}

#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/syscall/dispatch.hpp"

namespace junction {

bool is_dispatcher_enabled = false;

void init_glibc_dispatcher() { is_dispatcher_enabled = true; }

unsigned long sys_dispatch(long syscall, long arg0, long arg1, long arg2,
                           long arg3, long arg4, long arg5) {
  if (unlikely(!is_dispatcher_enabled)) {
    long ret = ksys_default(syscall, arg0, arg1, arg2, arg3, arg4, arg5);
    return static_cast<unsigned long>(ret);
  }

  switch (syscall) {
    case SYS_getpid: {
      return usys_getpid();
    }
    // TODO(girfan): Enable this when we have a stable FileSystem backend.
    /*
    case SYS_openat: {
      int dirfd = static_cast<int>(arg0);
      const char *pathname = reinterpret_cast<char *>(arg1);
      int flags = static_cast<int>(arg2);
      mode_t mode = static_cast<mode_t>(arg3);
      int ret = usys_openat(dirfd, pathname, flags, mode);
      return static_cast<unsigned long>(ret);
    }
    case SYS_open: {
      const char *pathname = reinterpret_cast<char *>(arg0);
      int flags = static_cast<int>(arg1);
      mode_t mode = static_cast<mode_t>(arg2);
      int ret = usys_open(pathname, flags, mode);
      return static_cast<unsigned long>(ret);
    }
    case SYS_write: {
      int fd = static_cast<int>(arg0);
      const char *buf = reinterpret_cast<char *>(arg1);
      size_t len = static_cast<size_t>(arg2);
      ssize_t ret;
      if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
        ret = ksys_write(fd, buf, len);
      } else {
        ret = usys_write(fd, buf, len);
      }
      return static_cast<unsigned long>(ret);
    }
    */
    default: {
      long ret = ksys_default(syscall, arg0, arg1, arg2, arg3, arg4, arg5);
      return static_cast<unsigned long>(ret);
    }
  }
}

}  // namespace junction
