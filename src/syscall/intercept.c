#include "syscall/intercept.h"

#include <errno.h>
#include <fcntl.h>
#include <libsyscall_intercept_hook_point.h>
#include <linux/kernel-page-flags.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

#include "syscall/handlers.hpp"

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

int _syscall_intercept_enabled = 0;

// TODO(gohar): Do argument checking inside the handle_* functions.
// Pass the appropriate return code and result from inside the handle_*
// functions. Keep this file clean.
static int hook(long syscall_number, long arg0, long arg1, long arg2, long arg3,
                long arg4, long arg5, long* result) {
  if (unlikely(!is_syscall_intercept_enabled())) {
    return 1;
  }

  if (syscall_number == SYS_openat) {
    if (arg0 == STDIN_FILENO || arg0 == STDOUT_FILENO ||
        arg0 == STDERR_FILENO) {
      return 1;
    }
    *result = handle_openat((int)arg0, (const char*)arg1, (int)arg2);
    return 0;
  } else if (syscall_number == SYS_fstat) {
    *result = handle_fstat((int)arg0, (struct stat*)arg1);
    return 0;
  } else if (syscall_number == SYS_lseek) {
    *result = handle_lseek((int)arg0, (off_t)arg1, (int)arg2);
    return 0;
  } else if (syscall_number == SYS_read) {
    if (arg0 == STDIN_FILENO || arg0 == STDOUT_FILENO ||
        arg0 == STDERR_FILENO) {
      return 1;
    }
    *result = handle_read((int)arg0, (void*)arg1, (size_t)arg2);
    return 0;
  } else if (syscall_number == SYS_write) {
    if (arg0 == STDIN_FILENO || arg0 == STDOUT_FILENO ||
        arg0 == STDERR_FILENO) {
      return 1;
    }
    *result = handle_write((int)arg0, (const void*)arg1, (size_t)arg2);
    return 0;
  } else if (syscall_number == SYS_close) {
    if (arg0 == STDIN_FILENO || arg0 == STDOUT_FILENO ||
        arg0 == STDERR_FILENO) {
      return 1;
    }
    *result = handle_close((int)arg0);
    return 0;
  }

  // Pass any other syscalls to the kernel.
  return 1;
}

static __attribute__((constructor)) void init(void) {
  // Set up the callback function
  intercept_hook_point = hook;
  printf("Loaded LibOS syscall_intercept\n");
}
