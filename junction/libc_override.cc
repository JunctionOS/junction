
#include <cstring>
#include <utility>

#include "junction/bindings/runtime.h"

extern "C" {

#include <base/log.h>
#include <base/syscall.h>

#define write_msg(msg) syscall_write(2, msg, strlen(msg))

#ifndef PERMISSIVE_SECCOMP

void __cxa_throw(void *thrown_exception, void *pvtinfo, void (*dest)(void *)) {
  write_msg("Exception thrown in Junction's libc.\n");
  write_msg("Exception unwinding and backtrace is not supported.\n");
  write_msg("Rebuild with the PERMISSIVE_SECCOMP flag.\n");
  write_msg("Killing Junction instance.\n");
  syscall_exit(-1);
  std::unreachable();
}

[[noreturn]] void __assert_fail(const char *assertion, const char *file,
                                unsigned int line, const char *function) {
  write_msg("Assertion failed: ");
  write_msg(assertion);
  write_msg(" file: ");
  write_msg(file);
  if (function) {
    write_msg(" function: ");
    write_msg(function);
  }

  write_msg("\n");
  syscall_exit(-1);
  std::unreachable();
}

#endif
}