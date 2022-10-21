#include "jnct/memorysystem/memorysystem.hpp"

#include <assert.h>
#include <libsyscall_intercept_hook_point.h>
#include <string.h>
#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>

#include "spdlog/spdlog.h"

namespace junction {

constexpr int MMAP_FD = -1;
constexpr int MMAP_OFFSET = 0;

void* MemorySystem::mmap(void* addr, size_t length, int prot, int flags,
                         const File& file, off_t offset) {
  // Mmap anonymous memory; later we will copy the requested fd contents into
  // this memory region and hand this back to the caller.
  // TODO(gohar): Handle the prot and flags properly.
  auto res = syscall_no_intercept(SYS_mmap, addr, length, prot | PROT_WRITE,
                                  flags | MAP_ANONYMOUS, MMAP_FD, MMAP_OFFSET);
  {
    const int err = syscall_error_code(res);
    if (err != 0) {
      spdlog::error("Cannot mmap: {0}", strerror(err));
      return MAP_FAILED;
    }
  }

  // Get the appropriate parameters for copying memory from the file.
  const size_t file_size = file.size();
  const void* file_mem = file.memory(offset);
  const size_t bytes_to_copy = std::min(file_size - offset, length);

  // Copy the file contents into the anonymous memory region that we mmaped.
  void* mem = reinterpret_cast<void*>(res);
  std::memcpy(mem, file_mem, bytes_to_copy);
  _mem_to_length[mem] = length;

  return mem;
}

// TODO(gohar): What if the address given is not the start address of the range
// that we had mapped but somewhere in the middle of one of those regions??
int MemorySystem::munmap(void* addr, size_t length) {
  // Check if we have mmapped to this address before.
  const auto mem_iter = _mem_to_length.find(addr);
  if (mem_iter == _mem_to_length.end()) {
    spdlog::error("Invalid address for munmap");
    // Using this return value to distinguish from the -1 returned by munmap
    // syscall upon a failed munmap operation.
    return 1;
  }

  // Munmap this memory.
  auto res = syscall_no_intercept(SYS_munmap, addr, length);
  {
    const int err = syscall_error_code(res);
    if (err != 0) {
      spdlog::error("Cannot munmap: {0}", strerror(err));
      return err;
    }
  }

  // Remove the entry.
  _mem_to_length.erase(mem_iter);

  return res;
}

}  // namespace junction