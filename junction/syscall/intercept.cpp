#include "junction/syscall/intercept.hpp"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kernel-page-flags.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

#include <csignal>
#include <iostream>

#include "junction/syscall/handlers.hpp"

const char MANIFEST_PATH[] = "manifest.txt";

int _syscall_intercept_enabled = 1;

/* This hook is called every time a syscall is made from the application;
 * it will either forward it to the kernel or dispatch to a custom handler.
 */
static unsigned long hook(long syscall_number, long arg0 = 0, long arg1 = 0,
                          long arg2 = 0, long arg3 = 0, long arg4 = 0,
                          long arg5 = 0) {
  // Forward syscalls to the kernel if the intercept mode is not yet enabled.
  return handle_default(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);

  /*
  // Dispatch syscalls to their appropriate handlers.
  switch (syscall_number) {
    case SYS_openat:
      return handle_openat((int)arg0, (const char*)arg1, (int)arg2);
    case SYS_open:
      return handle_open((const char*)arg0, (int)arg1, (mode_t)arg2);
    case SYS_fstat:
      return handle_fstat((int)arg0, (struct stat*)arg1);
    case SYS_lseek:
      return handle_lseek((int)arg0, (off_t)arg1, (int)arg2);
    case SYS_read:
      return handle_read((int)arg0, (void*)arg1, (size_t)arg2);
    case SYS_write:
      return handle_write((int)arg0, (const void*)arg1, (size_t)arg2);
    case SYS_close:
      return handle_close((int)arg0);
    case SYS_mmap:
      return handle_mmap((void*)arg0, (size_t)arg1, (int)arg2, (int)arg3,
                         (int)arg4, (off_t)arg5);
    default:
      return handle_default(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
  }
  */
}

extern "C" {
unsigned long int junction_syscall0(int number) { return hook(number); }

unsigned long int junction_syscall1(int number, long arg1) {
  return hook(number, arg1);
}

unsigned long int junction_syscall2(int number, long arg1, long arg2) {
  return hook(number, arg1, arg2);
}

unsigned long int junction_syscall3(int number, long arg1, long arg2,
                                    long arg3) {
  return hook(number, arg1, arg2, arg3);
}

unsigned long int junction_syscall4(int number, long arg1, long arg2, long arg3,
                                    long arg4) {
  return hook(number, arg1, arg2, arg3, arg4);
}

unsigned long int junction_syscall5(int number, long arg1, long arg2, long arg3,
                                    long arg4, long arg5) {
  return hook(number, arg1, arg2, arg3, arg4, arg5);
}

unsigned long int junction_syscall6(int number, long arg1, long arg2, long arg3,
                                    long arg4, long arg5, long arg6) {
  return hook(number, arg1, arg2, arg3, arg4, arg5, arg6);
}
}
