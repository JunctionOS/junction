extern "C" {
#include <runtime/smalloc.h>
}

#include <memory>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/filesystem/linuxfs.h"
#include "junction/junction.h"
#include "junction/kernel/fs.h"
#include "junction/shim/backend/init.h"
#include "junction/syscall/seccomp.h"
#include "junction/syscall/syscall.h"

namespace junction {

std::shared_ptr<LinuxFileSystemManifest> init_fs_manifest() {
  auto manifest = std::make_shared<LinuxFileSystemManifest>();
  const unsigned int flags = 0;
  const std::vector<std::string> filepaths(
      {"/proc/*", "/lib64/*", "/lib/*", "/usr/*", "/home/*", "/etc/*"});
  for (const auto &filepath : filepaths) {
    manifest->Insert(filepath, flags);
  }
  return manifest;
}

Status<void> init() {
  std::shared_ptr<LinuxFileSystemManifest> manifest = init_fs_manifest();
  init_fs(new LinuxFileSystem(std::move(manifest)));
  init_seccomp();
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
