#pragma once

#include <sys/types.h>

#include <unordered_map>

#include "jnct/filesystem/file.hpp"

namespace junction {

class MemorySystem {
 public:
  MemorySystem() = default;
  ~MemorySystem() = default;

  /* disallow copy */
  MemorySystem(const MemorySystem& temp_obj) = delete;
  MemorySystem& operator=(const MemorySystem& temp_obj) = delete;

  void* mmap(void* addr, size_t length, int prot, int flags, const File& file,
             off_t offset);
  int munmap(void* addr, size_t length);

 private:
  std::unordered_map<void*, size_t> _mem_to_length;
};

}  // namespace junction