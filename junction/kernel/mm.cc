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

template <typename F>
void MemoryMap::ForEachOverlap(uintptr_t start, uintptr_t end, F func) {
  // We want the first interval [a,b) where b > start (first overlap)
  auto cur = vmareas_.upper_bound(start);
  while (cur != vmareas_.end() && cur->second.start < end) {
    VMArea &cur_vma = cur->second;
    bool do_erase = func(cur_vma);
    if (do_erase)
      cur = vmareas_.erase(cur);
    else
      cur++;
  }
}

void MemoryMap::UpdateProtection(uintptr_t start, uintptr_t end, int prot) {
  assert(lock_.IsHeld());
  ForEachOverlap(start, end, [&, this](VMArea &cur_vma) {
    // check to see if cur_vma begins before our target range.
    if (start > cur_vma.start) {
      // split the VMA, preserve the existing portion before our target start.
      VMArea preserved_left = cur_vma;
      preserved_left.end = start;
      vmareas_[start] = preserved_left;

      // update the start bounds of our current VMA,
      cur_vma.start = start;
    }

    // check if cur_vma extends past the end of our target range
    if (end < cur_vma.end) {
      // split the VMA; a new VMA with updated protections is added to the left
      // of the current VMA.
      VMArea new_left = cur_vma;
      new_left.end = end;
      new_left.prot = prot;
      vmareas_[end] = new_left;

      // update the start bound of the existing VMA
      cur_vma.start = end;
      return false;
    }

    // If we're here we know [start, end) surrounds [cur_start, cur_end)
    cur_vma.prot = prot;
    return false;
  });
}

void MemoryMap::ClearMapping(uintptr_t start, uintptr_t end) {
  assert(lock_.IsHeld());

  ForEachOverlap(start, end, [&, this](VMArea &cur_vma) {
    uintptr_t cur_start = cur_vma.start;
    uintptr_t cur_end = cur_vma.end;

    // [start, end) does not overlap on the left of [cur_start, cur_end).
    // Shorten cur_vma to [cur_start, start).
    if (start > cur_start) {
      VMArea vma = cur_vma;
      vma.end = start;
      vmareas_[start] = vma;
    }

    // [start, end) either overlaps on the right or surrounds [cur_start,
    // cur_end). Either way cur_end is being overwritten so remove it.
    if (end >= cur_end) return true;

    // [start, end) either overlaps on the left or is surrounded by
    // [cur_start, cur_end). Keep cur_end and shorten it to [end, cur_end).
    cur_vma.start = end;
    return false;
  });
}

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
