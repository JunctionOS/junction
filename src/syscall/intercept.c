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

  switch (syscall_number) {
    case SYS_openat:
      return handle_openat((int)arg0, (const char*)arg1, (int)arg2, result);
    case SYS_fstat:
      return handle_fstat((int)arg0, (struct stat*)arg1, result);
    case SYS_lseek:
      return handle_lseek((int)arg0, (off_t)arg1, (int)arg2, result);
    case SYS_read:
      return handle_read((int)arg0, (void*)arg1, (size_t)arg2, result);
    case SYS_write:
      return handle_write((int)arg0, (const void*)arg1, (size_t)arg2, result);
    case SYS_close:
      return handle_close((int)arg0, result);
    default:
      return STATUS_FWD_TO_KERNEL;
  }
}

static __attribute__((constructor)) void init(void) {
  // Set up the callback function
  intercept_hook_point = hook;
  printf("Loaded LibOS syscall_intercept\n");
}
