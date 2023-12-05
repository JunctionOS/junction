
#include <cstring>
#include <utility>

extern "C" {

#include <base/syscall.h>

[[noreturn]] void __assert_fail(const char *assertion, const char *file,
                                unsigned int line, const char *function) {
  syscall_write(2, "Assertion failed: ", strlen("Assertion failed: "));
  syscall_write(2, assertion, strlen(assertion));
  syscall_write(2, " file: ", strlen(" file: "));
  syscall_write(2, file, strlen(file));
  if (function) {
    syscall_write(2, " function: ", strlen(" function: "));
    syscall_write(2, function, strlen(function));
  }

  syscall_write(2, "\n", 1);
  syscall_exit(-1);
  std::unreachable();
}
}