#pragma once

#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "junction/syscall/handlers.hpp"

#define MAX_LINE_LENGTH 1000

// When set to enabled, only then syscall interception will be performed.
// Otherwise, all syscalls will be passed to the kernel.
extern int _syscall_intercept_enabled;

static int preload_files(const char* filelist_path) {
  const char PERM_FILE_STR[] = "O_RDONLY|O_CLOEXEC";
  const char PERM_DIR_STR[] = "O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY";

  FILE* filelist;
  char filepath[MAX_LINE_LENGTH];
  char permissions[MAX_LINE_LENGTH];

  filelist = fopen(filelist_path, "r");
  if (filelist == NULL) {
    return 1;
  }

  unsigned long num_files = 0;
  while (fgets(filepath, MAX_LINE_LENGTH, filelist)) {
    filepath[strcspn(filepath, "\n")] = 0;
    if (fgets(permissions, MAX_LINE_LENGTH, filelist)) {
      permissions[strcspn(permissions, "\n")] = 0;
      if (strcmp(PERM_FILE_STR, permissions) == 0) {
        preload_file(filepath, O_RDONLY | O_CLOEXEC);
      } else if (strcmp(PERM_DIR_STR, permissions) == 0) {
        preload_file(filepath, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_DIRECTORY);
      } else {
        printf("Cannot preload. Unkown permissions: %s (%s)\n", filepath,
               permissions);
      }
      num_files++;
    } else {
      printf("Cannot preload. Permissions not found: %s\n", filepath);
    }
  }

  fclose(filelist);

  printf("Preloaded %lu files!\n", num_files);
  return 0;
}

static int enable_syscall_intercept() {
  _syscall_intercept_enabled = 1;
  printf("[junction]: Intercepting syscalls...\n");
  return 0;
}

static int disable_syscall_intercept() {
  _syscall_intercept_enabled = 0;
  printf("[junction]: Not intercepting syscalls...\n");
  return 0;
}

static int is_syscall_intercept_enabled() { return _syscall_intercept_enabled; }
