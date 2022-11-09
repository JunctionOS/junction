#include <dlfcn.h>
#include <error.h>
#include <fcntl.h>
#include <gnu/libc-version.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <csignal>

#include "junction/syscall/seccomp_filtering.hpp"

/* Perform syscalls using glibc. */
int test_glibc_syscall() {
  int fd = open("test.txt", O_RDONLY);

  if (fd == -1) {
    perror("open");
    return 1;
  }

  printf("fd = %d\n", fd);

  if (close(fd)) {
    perror("close");
    return 1;
  }

  return 0;
}

/* Perform *direct* syscalls without glibc. */
int test_direct_syscall() {
  int fd = syscall(SYS_open, "test.txt", O_RDONLY);

  if (fd == -1) {
    perror("open");
    return 1;
  }

  printf("fd = %d\n", fd);

  if (syscall(SYS_close, fd)) {
    perror("close");
    return 1;
  }

  return 0;
}

int main() {
  /* Check what version of glibc is being used. */
  printf("gnu_get_libc_version() = %s\n", gnu_get_libc_version());

  /* Log the PID. */
  pid_t pid = getpid();
  printf("PID = %d\n", pid);

  /* Enable libjunction. */
  if (junction::install_syscall_filter()) {
    printf("Cannot install syscall filter\n");
    return 1;
  }

  if (test_glibc_syscall()) {
    printf("Failed: test_glibc_syscall\n");
  } else {
    printf("Success: test_glibc_syscall\n");
  }

  if (test_direct_syscall()) {
    printf("Failed: test_direct_syscall\n");
  } else {
    printf("Success: test_direct_syscall\n");
  }

  return 0;
}
