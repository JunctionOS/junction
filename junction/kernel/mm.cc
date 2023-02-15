// mm.cc - memory management support
//
// TODO(amb): need to keep track of allocations for multiprocess

extern "C" {
#include <sys/mman.h>
}

#include "junction/kernel/file.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

int usys_brk(void *addr) {
  // TODO(amb): maybe this is broken? Instead allocate a heap?
  return brk(addr);
}

void *usys_mmap(void *addr, size_t length, int prot, int flags, int fd,
                off_t offset) {
  // Map anonymous memory.
  if ((flags & MAP_ANONYMOUS) != 0) {
    intptr_t ret = ksys_mmap(addr, length, prot, flags, fd, offset);
    if (ret < 0) return MAP_FAILED;
    return reinterpret_cast<void *>(ret);
  }

  // Map a file.
  FileTable &ftbl = myproc().get_file_table();
  File *f = ftbl.Get(fd);
  if (unlikely(!f)) return MAP_FAILED;
  Status<void *> ret = f->MMap(addr, length, prot, flags, offset);
  if (!ret) return MAP_FAILED;
  return static_cast<void *>(*ret);
}

int usys_mprotect(void *addr, size_t len, int prot) {
  return ksys_mprotect(addr, len, prot);
}

int usys_munmap(void *addr, size_t length) { return ksys_munmap(addr, length); }

}  // namespace junction
