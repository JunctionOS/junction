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
#include <sys/sysmacros.h>
}

#include <iomanip>

#include "junction/base/finally.h"
#include "junction/bindings/log.h"
#include "junction/fs/file.h"
#include "junction/kernel/mm.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"

namespace junction {

// Lock protecting allocation of memory maps.
rt::Spin MemoryMap::mm_lock_;
// Next address used for memory map.
uintptr_t MemoryMap::mm_base_addr_{0x300000000000};
std::atomic_size_t MemoryMap::nr_non_reloc_maps_{0};

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
  if (is_non_reloc_) nr_non_reloc_maps_--;
}

bool MemoryMap::TryMergeRight(std::map<uintptr_t, VMArea>::iterator prev,
                              VMArea &rhs) {
  if (prev == vmareas_.end()) return false;
  const VMArea &lhs = prev->second;
  if (!MappingsMergeable(lhs, rhs)) return false;
  rhs.start = lhs.start;
  rhs.offset = lhs.offset;
  vmareas_.erase(prev);
  return true;
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

  memfs::MemFSStartTracer(*FSRoot::GetGlobalRoot().get_root().get());
}

Status<PageAccessTracer> MemoryMap::EndTracing() {
  rt::ScopedLock g(mu_);
  if (!tracer_) return MakeError(ENODATA);

  memfs::MemFSEndTracer();

  // Restore all VMAs
  auto prev_it = vmareas_.begin();
  for (auto it = vmareas_.begin(); it != vmareas_.end(); prev_it = it++) {
    VMArea &vma = it->second;
    if (vma.traced) {
      vma.traced = false;
      if (vma.prot != PROT_NONE) {
        Status<void> ret = KernelMProtect(vma.Addr(), vma.Length(), vma.prot);
        if (unlikely(!ret))
          LOG(WARN) << "tracer could not mprotect " << ret.error() << " "
                    << vma;
      }
    }
    TryMergeRight(prev_it, vma);
  }

  PageAccessTracer pt = std::move(*tracer_);
  tracer_.reset();
  assert(MappingsValid(vmareas_));
  return std::move(pt);
}

Status<void> MemoryMap::DumpTracerReport() {
  Status<PageAccessTracer> report = EndTracing();
  if (likely(!report)) return {};

  std::string pth = GetCfg().GetArg("mem-trace-out");
  if (pth.empty()) {
    LOG(INFO) << "memory trace:\n" << *report;
  } else {
    LOG(INFO) << "dumping memory trace to " << pth;
    Status<KernelFile> ord_file =
        KernelFile::Open(pth, O_CREAT | O_TRUNC, FileMode::kWrite, 0644);
    if (unlikely(!ord_file)) {
      LOG(WARN) << "failed to open ord file `" << pth
                << "`: " << ord_file.error();
      return MakeError(ord_file);
    }

    std::stringstream ord;
    ord << *report;
    std::string ordstr = ord.str();
    Status<void> ret = WriteFull(*ord_file, std::as_bytes(std::span{ordstr}));
    if (unlikely(!ret)) {
      LOG(WARN) << "failed to write memory trace: " << ret.error();
      return MakeError(ret);
    }
  }
  return {};
}

void MemoryMap::RecordHit(void *addr, size_t len, Time time,
                          int required_prot) {
  assert(tracer_);
  uintptr_t page = PageAlignDown(reinterpret_cast<uintptr_t>(addr));
  uintptr_t end = PageAlign(reinterpret_cast<uintptr_t>(addr) + len);
  rt::ScopedLock ul(mu_);
  for (; page < end; page += kPageSize)
    tracer_->RecordHit(page, time, required_prot);
}

// This function is called when there is a SIGSEGV and
// the tracer is detected to be running
//
// Note: the tracer is implemented by mapping all regions as PROT_NONE
// and subsequently intercepting the SIGSEGVs
bool MemoryMap::HandlePageFault(uintptr_t addr, int required_prot, Time time) {
  addr = PageAlignDown(addr);

  rt::SpinGuard g(mm_lock_);
  // In tracer mode, holding the global MM spin lock implies ownership of the
  // shared mutex.
  assert(!mu_.IsHeld());
  // Acquire the shared mutex anyways, so that we don't fail debug asserts.
  rt::ScopedLock l(mu_);

  // No race condition with beginning/ending tracing since the process is always
  // fully stopped during these operations.
  assert(tracer_);

  rt::RuntimeLibcGuard guard;

  auto it = Find(addr);
  if (unlikely(it == vmareas_.end())) {
    LOG(WARN) << "couldn't find VMA for page " << addr;
    return false;
  }

  VMArea &vma = it->second;

  // Checks if the type of access (@required_prot) is legal for this VMA. If the
  // access is invalid, don't record it since no data is accessed.
  if ((vma.prot & required_prot) == 0) return false;

  // This access should have succeeded but is failing - it must be because we
  // are tracing it.
  assert(!!vma.traced);

  // An mprotect may have forced us to remap an already touched page as
  // PROT_NONE. Record the hit regardless and restore permissions.
  tracer_->RecordHit(addr, time, required_prot);

  int reprot = vma.prot;
  // Don't restore write permissions unless this fault was a write.
  if (required_prot != PROT_WRITE) reprot &= ~PROT_WRITE;

  Status<void> ret =
      KernelMProtect(reinterpret_cast<void *>(addr), kPageSize, reprot);
  if (unlikely(!ret)) {
    LOG(ERR) << " failed to restore permission to page" << ret.error();
    return false;
  }

  return true;
}

// An mprotect during tracing may downgrade the permissions of a region. We need
// to immediately remove those permissions from all pages in the region,
// however, we don't want to effectively add back any permissions to pages that
// are marked as PROT_NONE because they haven't been accessed yet. Instead we
// just mark the entire region PROT_NONE, potentially allowing pages that have
// already been faulted in to fault again.
void __attribute__((cold)) TracerModifyProt(VMArea &vma, int new_prot) {
  int old_prot = std::exchange(vma.prot, new_prot);

  // Non traced VMAs should be updated immediately.
  if (!vma.traced) {
    Status<void> ret = KernelMProtect(vma.Addr(), vma.Length(), new_prot);
    if (unlikely(!ret))
      LOG(WARN) << "tracer could not mprotect " << ret.error() << " " << vma;
    return;
  }

  // check if old protections have bits that are not present in the new
  // protections. If we are not modifying the protection or only adding
  // protection bits, then we will rely on the fault handler to apply those
  // permissions page-wise.
  if ((old_prot & ~new_prot) == 0) return;

  Status<void> ret = KernelMProtect(vma.Addr(), vma.Length(), PROT_NONE);
  if (unlikely(!ret))
    LOG(WARN) << "tracer could not mprotect " << ret.error() << " " << vma;
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
    if (vma.prot == prot) {
      TryMergeRight(prev_it, vma);
      continue;
    }

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
      if (unlikely(TraceEnabled()))
        TracerModifyProt(left, prot);
      else
        left.prot = prot;
      TryMergeRight(prev_it, left);
      vmareas_.insert(it, std::pair(end, std::move(left)));
      TrimHead(vma, end);
      continue;
    }

    // If we're here we know [start, end) surrounds [vma.start, vma.end)
    if (unlikely(TraceEnabled()))
      TracerModifyProt(vma, prot);
    else
      vma.prot = prot;
    TryMergeRight(prev_it, vma);
  }

  // Try merging the next VMA after our stopping point.
  if (it != vmareas_.end()) TryMergeRight(prev_it, it->second);

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
    TryMergeRight(prev_it, it->second);
  }

  if (auto next_it = std::next(it); next_it != vmareas_.end()) {
    TryMergeRight(it, next_it->second);
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

std::string MemoryMap::get_bin_path() const {
  if (!binary_path_) return "[STALE]";
  std::string out;
  out.reserve(PATH_MAX);
  rt::RuntimeLibcGuard g;
  std::ostringstream ss(std::move(out));
  Status<void> ret = binary_path_->GetFullPath(ss);
  if (unlikely(!ret)) return "[STALE]";
  return ss.str();
}

Status<uintptr_t> MemoryMap::SetBreak(uintptr_t brk_addr) {
  // NOTE: Must save the unaligned address, but the mapping will still be
  // aligned to a page boundary.
  uintptr_t newbrk = brk_addr;

  // Return the current brk address if out of range.
  if (newbrk < mm_start_ || newbrk >= mm_end_) return brk_addr_;

  // Otherwise, try to adjust the brk address.
  rt::UniqueLock ul(mu_, rt::InterruptOrLock);
  if (!ul) return MakeError(EINTR);

  uintptr_t oldbrk = brk_addr_;

  // Stop here if the mapping has not changed after alignment.
  if (PageAlign(oldbrk) == PageAlign(newbrk)) {
    brk_addr_ = newbrk;
    return brk_addr_;
  }

  // Make sure we don't overlap with an mmapped region.
  auto it = vmareas_.upper_bound(brk_addr_);
  if (it != vmareas_.end() && it->second.start < PageAlign(newbrk))
    return brk_addr_;

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

    if (!(flags & MAP_FIXED)) {
      Status<uintptr_t> tmp = FindFreeRange(addr, len);
      if (!tmp) return MakeError(tmp);
      addr = reinterpret_cast<void *>(*tmp);
      flags |= MAP_FIXED;
    }

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

  // Modify() will make KernelMProtect calls if the tracer is on.
  if (likely(!TraceEnabled())) {
    Status<void> ret = KernelMProtect(addr, len, prot);
    if (!ret) return MakeError(ret);
  }

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
  // Note: we may need to map a PROT_NONE region to prevent Linux from placing
  // other VMAs here.
  Status<void> ret = KernelMUnmap(addr, len);
  if (!ret) return MakeError(ret);
  auto [start, end] = AddressToBounds(addr, len);
  Clear(start, end);
  return {};
}

Status<void> MemoryMap::MAdvise(void *addr, size_t len, int hint) {
  // check length and alignment
  if (!AddressValid(addr, len)) return MakeError(EINVAL);

  // Translate MADV_FREEs to MADV_DONTNEED to immediately zero a page.
  if (hint == MADV_FREE && GetCfg().madv_dontneed_remap()) hint = MADV_DONTNEED;

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

Status<uintptr_t> MemoryMap::FindFreeRange(void *hint, size_t len) {
  assert(mu_.IsHeld());
  assert(IsPageAligned(len));

  // Try to accomodate a hint.
  if (hint != nullptr && reinterpret_cast<uintptr_t>(hint) + len <= mm_end_) {
    auto [start, end] = AddressToBounds(hint, len);

    // Find the first region that ends after the start of the requested one.
    auto it = vmareas_.upper_bound(start);
    // If no such region exists or the next region starts after the requested
    // end, the hinted address can be used.
    if (it == vmareas_.end() || it->second.start >= end) return start;

    // Try to place the request just before @it.
    auto prev = std::prev(it);
    uintptr_t new_start = it->second.start - len;
    uintptr_t prev_end = prev == vmareas_.begin() ? brk_addr_ : prev->first;
    if (new_start >= prev_end) return new_start;

    // Try to place the request just after @it.
    auto next = std::next(it);
    uintptr_t new_end = it->first + len;
    uintptr_t next_start =
        next == vmareas_.end() ? mm_end_ : next->second.start;
    if (new_end <= next_start) return it->second.end;
  }

  // Iterate from mm_end_ backwards looking for free slots.
  uintptr_t prev_start = mm_end_;
  auto it = vmareas_.rbegin();
  while (it != vmareas_.rend() && prev_start - it->first < len) {
    prev_start = it->second.start;
    it++;
  }

  uintptr_t addr = prev_start - len;
  if (addr < brk_addr_) return MakeError(ENOMEM);
  return addr;
}

void MemoryMap::save(cereal::BinaryOutputArchive &ar) const {
  ar(mm_start_, mm_end_ - mm_start_, brk_addr_, cmd_line_);
  ar(vmareas_);
  if (!binary_path_ || binary_path_->WillBeSerialized())
    ar(true, binary_path_);
  else
    ar(false, get_bin_path());
}

void MemoryMap::load_and_construct(cereal::BinaryInputArchive &ar,
                                   cereal::construct<MemoryMap> &construct) {
  uintptr_t mm_start, len;
  ar(mm_start, len);

  RegisterMMRegion(mm_start, len);

  Status<void *> ret =
      KernelMMap(reinterpret_cast<void *>(mm_start), len, PROT_NONE, 0);
  if (!ret) throw std::bad_alloc();

  construct(*ret, len);
  ar(construct->brk_addr_, construct->cmd_line_);
  ar(construct->vmareas_);

  bool hasdent;
  ar(hasdent);
  if (hasdent) {
    ar(construct->binary_path_);
  } else {
    std::string path;
    ar(path);
    Status<std::shared_ptr<DirectoryEntry>> dent =
        LookupDirEntry(FSRoot::GetGlobalRoot(), path);
    if (dent) construct->binary_path_ = std::move(*dent);
  }
}

std::ostream &operator<<(std::ostream &os, const VMArea &vma) {
  uintptr_t offset = 0;
  ino_t inum = 0;
  int dev_major = 0;
  int dev_minor = 0;
  if (vma.type == VMType::kFile) {
    offset = vma.offset;
    struct stat buf;
    if (vma.file->Stat(&buf)) {
      inum = buf.st_ino;
      dev_major = major(buf.st_dev);
      dev_minor = minor(buf.st_dev);
    }
  }

  return os << std::hex << vma.start << "-" << vma.end << " "
            << vma.ProtString() << " " << std::setfill('0') << std::setw(8)
            << std::right << offset << " " << std::setw(2) << dev_major << ":"
            << std::setw(2) << dev_minor << " " << std::dec << std::setfill(' ')
            << std::setw(26) << std::left << inum << " " << vma.TypeString();
}

std::string MemoryMap::GetMappingsString() {
  std::ostringstream ss;
  {
    rt::ScopedSharedLock g(mu_);
    for (auto const &[end, vma] : vmareas_) ss << vma << "\n";
  }
  return ss.str();
}

void MemoryMap::LogMappings() {
  rt::ScopedSharedLock g(mu_);
  for (auto const &[end, vma] : vmareas_) LOG(INFO) << vma;
}

template <typename Callable, typename... Args>
auto __attribute__((cold)) TracerGuardMMDoCall(Callable &&func, Args &&...args)
  requires std::invocable<Callable, Args...>
{
  return CallOnSyscallStack([&] {
    rt::SpinGuard g(MemoryMap::global_lock());
    return std::forward<Callable>(func)(std::forward<Args>(args)...);
  });
}

template <typename Callable, typename... Args>
inline auto TracerGuardCheck(MemoryMap &mm, Callable &&func, Args &&...args)
  requires std::invocable<Callable, Args...>
{
  if (likely(!mm.TraceEnabled()))
    return std::forward<Callable>(func)(std::forward<Args>(args)...);

  return TracerGuardMMDoCall(std::forward<Callable>(func),
                             std::forward<Args>(args)...);
}

intptr_t usys_brk(void *addr) {
  MemoryMap &mm = myproc().get_mem_map();
  Status<uintptr_t> ret = TracerGuardCheck(
      mm, [&] { return mm.SetBreak(reinterpret_cast<uintptr_t>(addr)); });
  if (!ret) return MakeCErrorRestartSys(ret);
  return *ret;
}

intptr_t usys_mmap(void *addr, size_t len, int prot, int flags, int fd,
                   off_t offset) {
  MemoryMap &mm = myproc().get_mem_map();

  // Silently turn shmem requests into anonymous private memory.
  if ((flags & MAP_SHARED) && fd == -1) {
    flags &= ~MAP_SHARED;
    flags |= MAP_ANONYMOUS;
  } else if ((flags & MAP_SHARED_VALIDATE) == MAP_SHARED_VALIDATE) {
    // MAP_SHARED_VALIDATE happens to be (MAP_ANONYMOUS | MAP_SHARED). Remove
    // the anonymous flag so we hit the correct case below. Note that if fd is
    // -1 then we hit the case above instead of here.
    flags &= ~MAP_ANONYMOUS;
  }

  // Map anonymous memory.
  if ((flags & MAP_ANONYMOUS) != 0) {
    Status<void *> ret = TracerGuardCheck(
        mm, [&] { return mm.MMapAnonymous(addr, len, prot, flags); });
    if (!ret) return MakeCErrorRestartSys(ret);
    return reinterpret_cast<intptr_t>(*ret);
  }

  // Map a file.
  FileTable &ftbl = myproc().get_file_table();
  std::shared_ptr<File> f = ftbl.Dup(fd);
  if (!f) return -EBADF;
  Status<void *> ret = TracerGuardCheck(mm, [&] {
    return mm.MMap(addr, len, prot, flags, std::move(f), offset);
  });
  if (!ret) return MakeCErrorRestartSys(ret);
  return reinterpret_cast<intptr_t>(*ret);
}

long usys_mprotect(void *addr, size_t len, int prot) {
  MemoryMap &mm = myproc().get_mem_map();
  Status<void> ret =
      TracerGuardCheck(mm, [&] { return mm.MProtect(addr, len, prot); });
  if (!ret) return MakeCErrorRestartSys(ret);
  return 0;
}

long usys_munmap(void *addr, size_t len) {
  MemoryMap &mm = myproc().get_mem_map();
  Status<void> ret = TracerGuardCheck(mm, [&] { return mm.MUnmap(addr, len); });
  if (!ret) return MakeCErrorRestartSys(ret);
  return 0;
}

long usys_madvise(void *addr, size_t len, int hint) {
  MemoryMap &mm = myproc().get_mem_map();
  Status<void> ret =
      TracerGuardCheck(mm, [&] { return mm.MAdvise(addr, len, hint); });
  if (!ret) return MakeCErrorRestartSys(ret);
  return 0;
}

}  // namespace junction
