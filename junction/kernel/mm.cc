// mm.cc - memory management support
//
// The Linux Kernel uses a read-writer mutex to protect VMAs. This can limit
// its concurrency, so we do the same here when performing memory system calls
// to avoid blocking in kthreads. This allows Junction to run other uthreads
// while waiting for system calls to return.
//
// Separately, Junction maintains its own VMAs in userspace. These mirror those
// in the Linux Kernel, but allow each process to track its subset of the
// mappings. VMAs in Junction are also useful for snapshotting processes and
// tearing down process memory.

extern "C" {
#include <sys/mman.h>
}

#include <iomanip>

#include "junction/base/finally.h"
#include "junction/bindings/log.h"
#include "junction/kernel/file.h"
#include "junction/kernel/mm.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

namespace {

constexpr std::pair<uintptr_t, uintptr_t> AddressToBounds(void *addr,
                                                          size_t len) {
  assert(AddressValid(addr, len));
  uintptr_t start = reinterpret_cast<uintptr_t>(addr);
  uintptr_t end = PageAlign(start + len);
  return std::make_pair(start, end);
}

constexpr bool MappingsMergeable(const VMArea &lhs, const VMArea &rhs) {
  // check general merge criteria
  if (lhs.end != rhs.start || lhs.type != rhs.type || lhs.prot != rhs.prot)
    return false;
  // Traced bit is not propagated.
  if (lhs.traced != rhs.traced) return false;
  // check file-specific merge criteria
  if (lhs.type == VMType::kFile) {
    assert(rhs.type == VMType::kFile);
    if (lhs.offset + static_cast<off_t>(lhs.Length()) != rhs.offset)
      return false;
    if (lhs.file != rhs.file) return false;
  }

  return true;
}

bool MergeRight(const VMArea &lhs, VMArea &rhs) {
  if (!MappingsMergeable(lhs, rhs)) return false;
  // do the merge
  rhs.start = lhs.start;
  rhs.offset = lhs.offset;
  return true;
}

bool MappingsValid(const std::map<uintptr_t, VMArea> &vmareas) {
  uintptr_t last_end = 0;

  auto it = vmareas.begin();
  auto prev = it;
  while (it != vmareas.end()) {
    const VMArea &vma = it->second;
    if (it->first != vma.end) return false;
    if (vma.start >= vma.end) return false;
    if (!IsPageAligned(vma.start) || !IsPageAligned(vma.end)) return false;
    if (vma.type == VMType::kFile && !vma.file) return false;
    if (vma.type != VMType::kFile && vma.file) return false;
    if (last_end > vma.start) return false;
    if (MappingsMergeable(prev->second, vma)) return false;
    last_end = vma.end;
    prev = it++;
  }

  return true;
}

void TrimHead(VMArea &vma, uintptr_t new_start) {
  assert(vma.start < new_start);
  if (vma.type == VMType::kFile) vma.offset += new_start - vma.start;
  vma.start = new_start;
}

void TrimTail(VMArea &vma, uintptr_t new_end) {
  assert(vma.end > new_end);
  vma.end = new_end;
}

}  // namespace

MemoryMap::~MemoryMap() {
  for (auto const &[end, vma] : vmareas_) {
    Status<void> ret = KernelMUnmap(vma.Addr(), vma.Length());
    if (!ret) LOG(ERR) << "mm: munmap failed with error " << ret.error();
  }
}

std::map<uintptr_t, VMArea>::iterator MemoryMap::Clear(uintptr_t start,
                                                       uintptr_t end) {
  assert(mu_.IsHeld());

  // We want the first interval [a,b] where b > start (first overlap)
  auto it = vmareas_.upper_bound(start);
  while (it != vmareas_.end() && it->second.start < end) {
    VMArea &vma = it->second;

    // [start, end) does not overlap on the left of [cur_start, cur_end).
    // Shorten cur_vma to [cur_start, start).
    if (start > vma.start) {
      VMArea left = vma;
      TrimTail(left, start);
      vmareas_.insert(it, std::pair(start, std::move(left)));
    }

    // [start, end) either overlaps on the right or surrounds [vma.start,
    // vma.end). Either way vma.end is being overwritten so remove it.
    if (end >= vma.end) {
      it = vmareas_.erase(it);
      continue;
    }

    // [start, end) either overlaps on the left or is surrounded by
    // [vma.start, vma.end). Keep vma.end and shorten it to [end, vma.end).
    TrimHead(vma, end);
    it++;
  }

  assert(MappingsValid(vmareas_));
  return it;
}

std::map<uintptr_t, VMArea>::iterator MemoryMap::Find(uintptr_t addr) {
  assert(mu_.IsHeld());
  assert(MappingsValid(vmareas_));
  auto it = vmareas_.upper_bound(addr);
  if (it == vmareas_.end() || it->second.start > addr) return vmareas_.end();
  return it;
}

void MemoryMap::EnableTracing() {
  rt::ScopedLock g(mu_);

  tracer_.reset(new PageAccessTracer());
  for (auto &[end, vma] : vmareas_) {
    vma.traced = true;
    if (vma.prot == PROT_NONE) continue;
    Status<void> ret = KernelMProtect(vma.Addr(), vma.Length(), PROT_NONE);
    if (unlikely(!ret))
      LOG(WARN) << "tracer could not mprotect " << ret.error() << " " << vma;
  }
}

void MemoryMap::EndTracing() {
  rt::ScopedLock g(mu_);
  if (!tracer_) return;

  // Restore all VMAs
  auto prev_it = vmareas_.begin();
  for (auto it = vmareas_.begin(); it != vmareas_.end(); prev_it = it++) {
    auto &[end, vma] = *it;
    if (vma.traced) {
      vma.traced = false;
      if (vma.prot != PROT_NONE) {
        Status<void> ret = KernelMProtect(vma.Addr(), vma.Length(), vma.prot);
        if (unlikely(!ret))
          LOG(WARN) << "tracer could not mprotect " << ret.error() << " "
                    << vma;
      }
    }
    if (MergeRight(prev_it->second, vma)) vmareas_.erase(prev_it);
  }

  assert(MappingsValid(vmareas_));

  // Sort accesses by time
  std::map<Time, uintptr_t> mp;
  for (auto const &[page, time] : tracer_->access_at_) mp.emplace(time, page);

  uint64_t page_cnt = 0, nz_page_cnt = 0;
  for (auto const &[time, page] : mp) {
    auto it = Find(page);
    if (it == vmareas_.end()) {
      LOG(WARN) << "skipping unknown VMA";
      continue;
    }

    LOG(INFO) << time.Microseconds() << ": " << (void *)page << " "
              << it->second.TypeString();
    page_cnt++;
    if (tracer_->non_zero_bytes_.at(page) > 0) nz_page_cnt++;
  }

  LOG(INFO) << "Total pages: " << page_cnt
            << " Non-zero pages: " << nz_page_cnt;
  tracer_.reset();
}

bool MemoryMap::HandlePageFault(uintptr_t addr, Time time) {
  if (unlikely(!tracer_)) return false;

  addr = PageAlignDown(addr);

  rt::UniqueLock ul(mu_, rt::DeferLock);
  if (likely(preempt_enabled())) {
    ul.Lock();
  } else {
    // We can't block when preemption is disabled.
    while (!ul.TryLock()) CPURelax();
  }

  // Return if we've already hit this page.
  rt::RuntimeLibcGuard guard;

  auto it = Find(addr);
  if (unlikely(it == vmareas_.end())) {
    LOG(WARN) << "couldn't find VMA for page " << addr;
    return false;
  }

  VMArea &vma = it->second;
  if (!vma.traced) return false;
  if (!tracer_->RecordHit(addr, time)) return true;
  if (unlikely(vma.prot == PROT_NONE)) return false;

  Status<void> ret = KernelMProtect(reinterpret_cast<void *>(addr), kPageSize,
                                    vma.prot | PROT_READ);
  if (unlikely(!ret)) {
    LOG(ERR) << " failed to restore permission to page" << ret.error();
    return false;
  }

  uint8_t cnt = 0;
  uint8_t *uaddr = reinterpret_cast<uint8_t *>(addr);
  for (size_t i = 0; i < kPageSize / sizeof(*uaddr); i++) cnt += !!uaddr[i];
  tracer_->RecordBytes(addr, cnt);

  // Remove read permissions if needed.
  if ((vma.prot & PROT_READ) == 0) {
    ret = KernelMProtect(reinterpret_cast<void *>(addr), kPageSize, vma.prot);
    if (unlikely(!ret))
      LOG(ERR) << " failed to restore permission to page" << ret.error();
  }

  return true;
}

void MemoryMap::Modify(uintptr_t start, uintptr_t end, int prot) {
  assert(mu_.IsHeld());
  // TODO(amb): Should this function fail if there are unmapped gaps?

  // We want the first interval [a,b] where b > start
  auto it = vmareas_.upper_bound(start);
  auto prev_it = it == vmareas_.begin() ? vmareas_.end() : std::prev(it);
  while (it != vmareas_.end() && it->second.start < end) {
    auto f = finally([&prev_it, &it] { prev_it = it++; });
    VMArea &vma = it->second;

    // skip if the protection isn't changed
    if (vma.prot == prot) continue;

    // split the VMA to modify the right part? [start, vma.end)
    if (start > vma.start) {
      VMArea left = vma;
      TrimTail(left, start);
      vmareas_.insert(it, std::pair(start, std::move(left)));
      TrimHead(vma, start);
    }

    // split the VMA to modify the left part? [vma.start, end)
    if (end < vma.end) {
      VMArea left = vma;
      TrimTail(left, end);
      left.prot = prot;
      if (prev_it != vmareas_.end() && MergeRight(prev_it->second, left))
        vmareas_.erase(prev_it);
      vmareas_.insert(it, std::pair(end, std::move(left)));
      TrimHead(vma, end);
      continue;
    }

    // If we're here we know [start, end) surrounds [vma.start, vma.end)
    vma.prot = prot;
    if (prev_it != vmareas_.end() && MergeRight(prev_it->second, vma))
      vmareas_.erase(prev_it);
  }

  // Try merging the next VMA after our stopping point.
  if (prev_it != vmareas_.end() && it != vmareas_.end() &&
      MergeRight(prev_it->second, it->second))
    vmareas_.erase(prev_it);

  assert(MappingsValid(vmareas_));
}

void MemoryMap::Insert(VMArea &&vma) {
  assert(mu_.IsHeld());

  // overlapping mappings must be atomically cleared
  auto it = Clear(vma.start, vma.end);

  // then insert the new mapping
  it = vmareas_.insert(it, std::pair(vma.end, std::move(vma)));

  // finally, try to merge with adjacent mappings
  if (it != vmareas_.begin()) {
    auto prev_it = std::prev(it);
    if (MergeRight(prev_it->second, it->second)) vmareas_.erase(prev_it);
  }
  if (auto next_it = std::next(it); next_it != vmareas_.end()) {
    if (MergeRight(it->second, next_it->second)) vmareas_.erase(it);
  }

  assert(MappingsValid(vmareas_));
}

std::vector<VMArea> MemoryMap::get_vmas() {
  std::vector<VMArea> tmp;
  rt::ScopedSharedLock g(mu_);
  tmp.reserve(vmareas_.size());
  for (auto const &[end, vma] : vmareas_) tmp.push_back(vma);
  return tmp;
}

Status<uintptr_t> MemoryMap::SetBreak(uintptr_t brk_addr) {
  // NOTE: Must save the unaligned address, but the mapping will still be
  // aligned to a page boundary.
  uintptr_t newbrk = brk_addr;

  // Return the current brk address if out of range.
  if (newbrk < brk_start_ || newbrk >= brk_end_) return brk_addr_;

  // Otherwise, try to adjust the brk address.
  rt::UniqueLock ul(mu_, rt::InterruptOrLock);
  if (!ul) return MakeError(EINTR);
  uintptr_t oldbrk = brk_addr_;

  // Stop here if the mapping has not changed after alignment.
  if (PageAlign(oldbrk) == PageAlign(newbrk)) {
    brk_addr_ = newbrk;
    return brk_addr_;
  }

  if (newbrk > oldbrk) {
    // Grow the heap mapping.
    void *addr = reinterpret_cast<void *>(PageAlign(oldbrk));
    size_t len = PageAlign(newbrk) - PageAlign(oldbrk);
    Status<void> ret = KernelMMapFixed(addr, len, PROT_READ | PROT_WRITE, 0);
    if (!ret) {
      LOG(ERR) << "mm: growing brk address failed. " << ret.error();
      return brk_addr_;
    }
    Insert(VMArea(addr, len, PROT_READ | PROT_WRITE, VMType::kHeap));
  } else {
    void *addr = reinterpret_cast<void *>(PageAlign(newbrk));
    size_t len = PageAlign(oldbrk) - PageAlign(newbrk);
    // Shrink the heap mapping.
    Status<void> ret = KernelMMapFixed(addr, len, PROT_NONE, 0);
    if (!ret) {
      LOG(ERR) << "mm: shrinking brk address failed. " << ret.error();
      return brk_addr_;
    }
    auto [start, end] = AddressToBounds(addr, len);
    Clear(start, end);
  }

  // Success; update brk address and return.
  brk_addr_ = newbrk;
  return brk_addr_;
}

Status<void *> MemoryMap::MMap(void *addr, size_t len, int prot, int flags,
                               std::shared_ptr<File> f, off_t off) {
  // the shared modes are currently unsupported
  if ((flags & MAP_SHARED) != 0) {
    LOG_ONCE(ERR) << "mm: shared mmap() mappings are unsupported";
    // FIXME(amb): Java requires us to continue here to run
    // return MakeError(EINVAL);
  }

  // check length and alignment
  if (!AddressValid(addr, len)) return MakeError(EINVAL);

  // check if pages should be populated (i.e., read-ahead faulted)
  bool do_populate = (flags & MAP_POPULATE);
  flags &= ~MAP_POPULATE;

  // length must be aligned up to the nearest page
  len = PageAlign(len);

  // do the mapping
  Status<void *> raddr;
  {
    rt::UniqueLock ul(mu_, rt::InterruptOrLock);
    if (!ul) return MakeError(EINTR);
    VMArea vma;
    if (flags & MAP_ANONYMOUS) {
      // anonymous memory
      raddr = KernelMMap(addr, len, prot, flags);
      if (!raddr) return MakeError(raddr);
      VMType type = (flags & MAP_STACK) != 0 ? VMType::kStack : VMType::kNormal;
      vma = VMArea(*raddr, len, prot, type);
    } else {
      // file-backed memory (Linux ignores MAP_FILE)
      if (!f) return MakeError(EBADF);
      raddr = f->MMap(addr, len, prot, flags, off);
      if (!raddr) return MakeError(raddr);
      vma = VMArea(*raddr, len, prot, std::move(f), off);
    }
    Insert(std::move(vma));
  }

  // populate the mapping (if requested)
  if (do_populate) {
    Status<void> ret = MAdvise(*raddr, len, MADV_POPULATE_READ);
    if (!ret && ret.error() == EINTR) return MakeError(EINTR);
  }

  return *raddr;
}

Status<void> MemoryMap::MProtect(void *addr, size_t len, int prot) {
  // check length and alignment
  if (!AddressValid(addr, len)) return MakeError(EINVAL);

  // change protections
  rt::UniqueLock ul(mu_, rt::InterruptOrLock);
  if (!ul) return MakeError(EINTR);
  Status<void> ret = KernelMProtect(addr, len, prot);
  if (!ret) return MakeError(ret);
  auto [start, end] = AddressToBounds(addr, len);
  Modify(start, end, prot);
  return {};
}

Status<void> MemoryMap::MUnmap(void *addr, size_t len) {
  // check length and alignment
  if (!AddressValid(addr, len)) return MakeError(EINVAL);

  // clear mappings
  rt::UniqueLock ul(mu_, rt::InterruptOrLock);
  if (!ul) return MakeError(EINTR);
  Status<void> ret = KernelMUnmap(addr, len);
  if (!ret) return MakeError(ret);
  auto [start, end] = AddressToBounds(addr, len);
  Clear(start, end);
  return {};
}

Status<void> MemoryMap::MAdvise(void *addr, size_t len, int hint) {
  // check length and alignment
  if (!AddressValid(addr, len)) return MakeError(EINVAL);

  // If enabled, MADV_DONTNEED explicitly drops pages by mapping a new region
  // over the existing one. This allows the page tracer to accurately account
  // for these pages.
  if (hint == MADV_DONTNEED && GetCfg().madv_dontneed_remap()) {
    rt::UniqueLock ul(mu_, rt::InterruptOrLock);
    if (!ul) return MakeError(EINTR);

    auto [start, end] = AddressToBounds(addr, len);
    auto it = vmareas_.upper_bound(start);
    while (it != vmareas_.end() && it->second.start < end) {
      auto f = finally([&it] { it++; });
      VMArea &vma = it->second;

      // The contents of file-backed mappings are unchanged by MADV_DONTNEED.
      if (vma.type == VMType::kFile) continue;

      uintptr_t begin = std::max(start, vma.start);
      Status<void> ret =
          KernelMMapFixed(reinterpret_cast<void *>(begin),
                          std::min(end, vma.end) - begin, vma.prot, 0);
      if (unlikely(!ret)) {
        LOG(ERR) << "failed to remap for MADV_DONTNEED " << ret.error();
      }
    }

    return {};
  }

  // provide mapping hints
  rt::SharedLock ul(mu_, rt::InterruptOrLock);
  if (!ul) return MakeError(EINTR);
  return KernelMAdvise(addr, len, hint);
}

size_t MemoryMap::VirtualUsage() {
  size_t usage = 0;
  rt::ScopedSharedLock g(mu_);
  for (auto const &[end, vma] : vmareas_) usage += vma.Length();
  return usage;
}

std::ostream &operator<<(std::ostream &os, const VMArea &vma) {
  uintptr_t offset = vma.type == VMType::kFile ? vma.offset : 0;
  return os << std::hex << "0x" << vma.start << "-0x" << vma.end << " "
            << vma.ProtString() << " " << std::setw(8) << offset << " "
            << vma.TypeString();
}

void MemoryMap::LogMappings() {
  rt::ScopedSharedLock g(mu_);
  for (auto const &[end, vma] : vmareas_) LOG(INFO) << vma;
}

intptr_t usys_brk(uintptr_t addr) {
  MemoryMap &mm = myproc().get_mem_map();
  Status<uintptr_t> ret = mm.SetBreak(addr);
  if (!ret) return MakeCError(ret);
  return *ret;
}

intptr_t usys_mmap(void *addr, size_t len, int prot, int flags, int fd,
                   off_t offset) {
  MemoryMap &mm = myproc().get_mem_map();

  // Map anonymous memory.
  if ((flags & MAP_ANONYMOUS) != 0) {
    Status<void *> ret = mm.MMapAnonymous(addr, len, prot, flags);
    if (!ret) return MakeCError(ret);
    return reinterpret_cast<intptr_t>(*ret);
  }

  // Map a file.
  FileTable &ftbl = myproc().get_file_table();
  std::shared_ptr<File> f = ftbl.Dup(fd);
  if (!f) return -EBADF;
  Status<void *> ret = mm.MMap(addr, len, prot, flags, std::move(f), offset);
  if (!ret) return MakeCError(ret);
  return reinterpret_cast<intptr_t>(*ret);
}

int usys_mprotect(void *addr, size_t len, int prot) {
  MemoryMap &mm = myproc().get_mem_map();
  Status<void> ret = mm.MProtect(addr, len, prot);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_munmap(void *addr, size_t len) {
  MemoryMap &mm = myproc().get_mem_map();
  Status<void> ret = mm.MUnmap(addr, len);
  if (!ret) return MakeCError(ret);
  return 0;
}

int usys_madvise(void *addr, size_t len, int hint) {
  MemoryMap &mm = myproc().get_mem_map();
  Status<void> ret = mm.MAdvise(addr, len, hint);
  if (!ret) return MakeCError(ret);
  return 0;
}

}  // namespace junction
