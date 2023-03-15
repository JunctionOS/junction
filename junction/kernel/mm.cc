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
    KernelMMapFixed(reinterpret_cast<void *>(PageAlign(newbrk)),
                    PageAlign(oldbrk) - PageAlign(newbrk), PROT_NONE, 0);
    return newbrk;
  }

  // handle growing the heap.
  Status<void> ret = KernelMMapFixed(
      reinterpret_cast<void *>(PageAlign(oldbrk)),
      PageAlign(newbrk) - PageAlign(oldbrk), PROT_READ | PROT_WRITE, 0);
  if (unlikely(!ret))
    LOG(ERR) << "mm: Could not increase brk addr. (mmap() failed "
             << ret.error() << ").";
  return newbrk;
}

intptr_t usys_mmap(void *addr, size_t len, int prot, int flags, int fd,
                   off_t offset) {
  MemoryMap &mm = myproc().get_mem_map();
  if ((flags & MAP_FIXED) != 0) {
    if (!mm.IsWithin(addr, len))
      LOG_ONCE(WARN)
          << "mm: Fixed addr out of bounds; may interfere with other processes";
  } else {
    addr = mm.ReserveForMapping(len);
    if (unlikely(!addr)) {
      LOG(ERR) << "mm: Out of virtual memory.";
      return -ENOMEM;
    }
  }

  // Map anonymous memory.
  if ((flags & MAP_ANONYMOUS) != 0) {
    Status<void> ret = KernelMMapFixed(addr, len, prot, flags);
    if (!ret) return MakeCError(ret);
    return reinterpret_cast<intptr_t>(addr);
  }

  // Map a file.
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return -EBADF;
  Status<void *> ret = f->MMap(addr, len, prot, flags | MAP_FIXED, offset);
  if (!ret) return MakeCError(ret);
  return reinterpret_cast<intptr_t>(*ret);
}

int usys_mprotect(void *addr, size_t len, int prot) {
  return ksys_mprotect(addr, len, prot);
}

int usys_munmap(void *addr, size_t len) {
  Status<void> ret = KernelMMapFixed(addr, len, PROT_NONE, 0);
  if (unlikely(!ret)) return MakeCError(ret);
  MemoryMap &mm = myproc().get_mem_map();
  mm.ReturnForMapping(addr, len);
  return 0;
}

long usys_madvise(void *addr, size_t length, int advice) {
  if (advice != MADV_DONTNEED) return -EINVAL;
  return ksys_madvise(addr, length, advice);
}

}  // namespace junction
