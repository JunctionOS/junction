
#include <cstring>
#include <exception>
#include <utility>

#include "junction/bindings/runtime.h"
#include "junction/junction.h"
#include "junction/kernel/ksys.h"

extern "C" {
#include <base/log.h>
#include <base/syscall.h>

#ifndef PERMISSIVE_SECCOMP

/* With -static-libstdc++, define __wrap___cxa_throw and forward early-exit
 * paths to
 * __real___cxa_throw (see -Wl,--wrap=__cxa_throw in junction/CMakeLists.txt).
 */
void __real___cxa_throw(void *thrown_exception, void *pvtinfo,
                        void (*dest)(void *));

#define write_msg(msg) syscall_write(2, msg, strlen(msg))
#define write_msg_var(msg) syscall_write(2, msg, __strlen(msg))

static size_t __strlen(const char *msg) {
  size_t len;
  for (len = 0; *msg; msg++, len++)
    ;
  return len;
}

void __wrap___cxa_throw(void *thrown_exception, void *pvtinfo,
                        void (*dest)(void *)) {
  if (!junction::IsRuntimeReady()) {
    __real___cxa_throw(thrown_exception, pvtinfo, dest);
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
  junction::ksys_exit(-1);
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
  junction::ksys_exit(-1);
  std::unreachable();
}

#endif
}
