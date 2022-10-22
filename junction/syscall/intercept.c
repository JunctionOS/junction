#include "jnct/syscall/intercept.h"

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
#include <pthread.h>
#include <dlfcn.h>

#include "jnct/syscall/handlers.hpp"

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

const char MANIFEST_PATH[] = "manifest.txt";

int _syscall_intercept_enabled = 0;

/* This hook is called every time a syscall is made from the application;
 * it will either forward it to the kernel or dispatch to a custom handler.
 */
static int hook(long syscall_number, long arg0, long arg1, long arg2, long arg3,
                long arg4, long arg5, long* result) {
  // Forward syscalls to the kernel if the intercept mode is not yet enabled.
  if (unlikely(!is_syscall_intercept_enabled())) {
    return STATUS_FWD_TO_KERNEL;
  }

  // Dispatch syscalls to their appropriate handlers.
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
    case SYS_mmap:
      return handle_mmap((void*)arg0, (size_t)arg1, (int)arg2, (int)arg3,
        (int)arg4, (off_t)arg5, result);
    default:
      return STATUS_FWD_TO_KERNEL;
  }
}

// TODO(gohar): Temporary way to do delayed interception; this allows the setup
// phase of the application to go without any interception.
void* _do_initialization(void* p) {
  printf("[junction]: Sleeping...\n");
  sleep(3);
  enable_syscall_intercept();
  pthread_exit(NULL);
}

void start_initialization() {
  pthread_t init_thread;
  pthread_create(&init_thread, NULL, _do_initialization, NULL);
}

static __attribute__((constructor)) void init(void) {
  if (preload_files(MANIFEST_PATH)) {
    printf("[junction]: Cannot load manifest, skipping...\n");
  }

  start_initialization();

  // Set up the syscall interception hook.
  intercept_hook_point = hook;
}
