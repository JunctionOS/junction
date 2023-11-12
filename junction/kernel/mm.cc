// mm.cc - memory management support

extern "C" {
#include <sys/mman.h>
}

#include "junction/base/arch.h"
#include "junction/bindings/log.h"
#include "junction/kernel/file.h"
#include "junction/kernel/mm.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

uintptr_t usys_brk(uintptr_t addr) {
  MemoryMap &mm = myproc().get_mem_map();
  uintptr_t oldbrk = mm.GetBreak();
  if (addr == 0) return oldbrk;
  uintptr_t newbrk = mm.SetBreak(addr);

  // check if out of virtual memory.
  if (unlikely(newbrk != addr)) {
    LOG(ERR) << "mm: Out of virtual memory.";
    return oldbrk;
  }

  // check if the amount requested already lands on the current page.
  if (PageAlign(newbrk) == PageAlign(oldbrk)) return newbrk;

  // handle shrinking the heap.
  if (newbrk < oldbrk) {
    mm.MMap(reinterpret_cast<void *>(PageAlign(newbrk)),
            PageAlign(oldbrk) - PageAlign(newbrk), PROT_NONE, MAP_FIXED,
            VMType::kMemory);
    return newbrk;
  }

  // handle growing the heap.
  Status<void *> ret =
      mm.MMap(reinterpret_cast<void *>(PageAlign(oldbrk)),
              PageAlign(newbrk) - PageAlign(oldbrk), PROT_READ | PROT_WRITE,
              MAP_FIXED, VMType::kHeap);
  if (unlikely(!ret))
    LOG(ERR) << "mm: Could not increase brk addr. (mmap() failed "
             << ret.error() << ").";
  return newbrk;
}

intptr_t usys_mmap(void *addr, size_t len, int prot, int flags, int fd,
                   off_t offset) {
  MemoryMap &mm = myproc().get_mem_map();

  // Map anonymous memory.
  if ((flags & MAP_ANONYMOUS) != 0) {
    auto type = VMType::kMemory;
    if (flags & MAP_STACK) type = VMType::kStack;
    Status<void *> ret = mm.MMap(addr, len, prot, flags, type);
    if (!ret) return MakeCError(ret);
    return reinterpret_cast<intptr_t>(*ret);
  }

  // Map a file.
  FileTable &ftbl = myproc().get_file_table();
  std::shared_ptr<File> f = ftbl.Dup(fd);
  if (unlikely(!f)) return -EBADF;
  Status<void *> ret = mm.MMap(f, addr, len, prot, flags, offset);
  if (!ret) return MakeCError(ret);
  return reinterpret_cast<intptr_t>(*ret);
}

int usys_mprotect(void *addr, size_t len, int prot) {
  MemoryMap &mm = myproc().get_mem_map();
  Status<void> ret = mm.MProtect(addr, len, prot);
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

int usys_munmap(void *addr, size_t len) {
  MemoryMap &mm = myproc().get_mem_map();
  Status<void> ret = mm.MUnmap(addr, len);
  if (unlikely(!ret)) return MakeCError(ret);
  return 0;
}

long usys_madvise(void *addr, size_t length, int advice) {
  return ksys_madvise(addr, length, advice);
}

}  // namespace junction
