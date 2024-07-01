
#include <cstring>
#include <exception>
#include <utility>

#include "junction/bindings/runtime.h"
#include "junction/junction.h"

extern "C" {
#include <base/log.h>
#include <base/syscall.h>
#include <dlfcn.h>

#define write_msg(msg) syscall_write(2, msg, strlen(msg))
#define write_msg_var(msg) syscall_write(2, msg, __strlen(msg))

#ifndef PERMISSIVE_SECCOMP

static size_t __strlen(const char *msg) {
  size_t len;
  for (len = 0; *msg; msg++, len++)
    ;
  return len;
}

void __cxa_throw(void *thrown_exception, void *pvtinfo, void (*dest)(void *)) {
  if (!junction::IsRuntimeReady()) {
    void *fn = dlsym(RTLD_NEXT, "__cxa_throw");
    reinterpret_cast<decltype(__cxa_throw) *>(fn)(thrown_exception, pvtinfo,
                                                  dest);
  }

  std::exception *ex = static_cast<std::exception *>(thrown_exception);
  const char *msg = ex->what();
  if (msg) {
    write_msg("Exception message: ");
    write_msg_var(msg);
    write_msg("\n\n");
  }
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
  write_msg_var(assertion);
  write_msg(" file: ");
  write_msg_var(file);
  if (function) {
    write_msg(" function: ");
    write_msg_var(function);
  }

  write_msg("\n");
  syscall_exit(-1);
  std::unreachable();
}

#endif
}