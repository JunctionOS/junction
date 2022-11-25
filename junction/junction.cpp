extern "C" {
#include <runtime/smalloc.h>
}

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/filesystem/linuxfs.hpp"
#include "junction/junction.hpp"
#include "junction/kernel/fs.h"
#include "junction/shim/backend/init.h"
#include "junction/syscall/seccomp.hpp"
#include "junction/syscall/syscall.hpp"

namespace junction {

Status<void> init() {
  set_fs(new LinuxFileSystem());
  install_seccomp_filter();
  Status<void> ret = SyscallInit();
  if (unlikely(!ret)) return MakeError(ret);

  ret = ShimJmpInit();
  if (unlikely(!ret)) return MakeError(ret);

  return {};
}

}  // namespace junction

// Override global new and delete operators
inline void *__new(size_t size) {
  if (likely(thread_self()))
    return smalloc(size);
  else
    return malloc(size);
}

void *operator new(size_t size, const std::nothrow_t &nothrow_value) noexcept {
  return __new(size);
}

void *operator new(size_t size) throw() {
  void *ptr = __new(size);
  if (unlikely(size && !ptr)) throw std::bad_alloc();
  return ptr;
}

void operator delete(void *ptr) noexcept {
  if (!ptr) return;
  if (likely(thread_self()))
    sfree(ptr);
  else
    ;  // memory is being freed at teardown, probably ok to leak?
}
