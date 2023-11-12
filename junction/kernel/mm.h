// mm.h - memory mapping support

#pragma once

#include <map>
#include <memory>

#include "junction/base/arch.h"
#include "junction/base/error.h"
#include "junction/bindings/sync.h"
#include "junction/kernel/file.h"
#include "junction/kernel/ksys.h"

namespace junction {

enum class VMType : int {
  kFile,
  kMemory,
  kHeap,
  kStack,
};

struct VMArea {
  uintptr_t start;
  uintptr_t end;
  off_t offset;
  int prot;
  int flags;
  std::shared_ptr<File> file;
  VMType type;
};

class alignas(kCacheLineSize) MemoryMap {
 public:
  MemoryMap(void *base, size_t len)
      : base_(reinterpret_cast<uintptr_t>(base)), len_(len), brk_addr_(base_) {
    VMArea vma = {base_,          base_ + PageAlign(len_),     0,
                  PROT_NONE,      MAP_ANONYMOUS | MAP_PRIVATE, nullptr,
                  VMType::kMemory};
    vmareas_[vma.end] = vma;
  }
  ~MemoryMap() {
    for (auto const &e : vmareas_) {
      const VMArea &vma = e.second;
      MUnmap(reinterpret_cast<void *>(vma.start), vma.end - vma.start);
    }
  }

  // Sets the break address (for the heap), or returns prior address if
  // invalid.
  uintptr_t SetBreak(uintptr_t addr) {
    if ((addr < base_) || (addr >= base_ + len_)) return brk_addr_;
    rt::SpinGuard g(lock_);
    brk_addr_ = addr;
    return addr;
  }

  // Gets the break address (for the heap).
  [[nodiscard]] uintptr_t GetBreak() const { return brk_addr_; }

  Status<void *> MMap(std::shared_ptr<File> f, void *addr, size_t len, int prot,
                      int flags, off_t off) {
    Status<void *> ret = f.get()->MMap(addr, len, prot, flags, off);
    if (!ret) return MakeError(ret);
    const VMArea vma = {
        reinterpret_cast<uintptr_t>(*ret),
        reinterpret_cast<uintptr_t>(*ret) + PageAlign(len),
        off,
        prot,
        flags,
        f,
        VMType::kFile,
    };
    rt::SpinGuard g(lock_);
    Insert(vma);
    return ret;
  }

  Status<void *> MMap(void *addr, size_t len, int prot, int flags,
                      VMType type) {
    Status<void *> ret = KernelMMap(addr, len, prot, flags);
    if (!ret) return MakeError(ret);
    const VMArea vma = {
        reinterpret_cast<uintptr_t>(*ret),
        reinterpret_cast<uintptr_t>(*ret) + PageAlign(len),
        0,
        prot,
        flags,
        nullptr,
        type,
    };
    rt::SpinGuard g(lock_);
    Insert(vma);
    return ret;
  }

  Status<void> MProtect(void *addr, size_t len, int prot) {
    Status<void> ret = KernelMProtect(addr, len, prot);
    if (!ret) return MakeError(ret);
    uintptr_t start = reinterpret_cast<uintptr_t>(addr);
    uintptr_t end = start + PageAlign(len);
    rt::SpinGuard g(lock_);
    auto cur = vmareas_.upper_bound(start);
    // we're guaranteed to have overlap because the mapping has to exist
    for (; cur != vmareas_.end(); cur++) {
      VMArea &cur_vma = cur->second;
      uintptr_t cur_start = cur_vma.start;
      uintptr_t cur_end = cur_vma.end;

      if (end <= cur_start) break;

      // We know cur_vma overlaps with [start, end) so there are
      // 3 scenarios: either [start, end) overlaps on the right, on the
      // left, or surrounds cur_vma.
      // We don't have to worry about the regions [start, cur_start) when
      // start < cur_start or [end, cur_end) when end > cur_end because they are
      // guaranteed to overlap with adjacent VMAs if KernelMProtect succeeds.

      // [start, end) overlaps on the right
      if (start > cur_start) {
        // preserve [cur_start, start)
        VMArea left = cur_vma;
        left.end = start;
        vmareas_[left.end] = left;

        // [start, cur_end) with new prot
        cur_vma.start = start;
        cur_vma.prot = prot;
        continue;
      }
      // [start, end) overlaps on the left
      if (end < cur_end) {
        // preserve [cur_start, end)
        VMArea left = cur_vma;
        left.end = end;
        left.prot = prot;
        vmareas_[left.end] = left;

        // create [end, cur_end) with new prot
        cur_vma.start = end;
        continue;
      }

      // If we're here we know [start, end) surrounds [cur_start, cur_end)
      cur_vma.prot = prot;
    }
    return ret;
  }

  Status<void> MUnmap(void *addr, size_t len) {
    Status<void> ret = KernelMUnmap(addr, len);
    if (!ret) return MakeError(ret);
    uintptr_t start = reinterpret_cast<uintptr_t>(addr);
    uintptr_t end = start + PageAlign(len);
    rt::SpinGuard g(lock_);
    ClearMapping(start, end);
    return ret;
  }

  // Returns true if the mapping is inside the reserved region.
  bool IsWithin(void *buf, size_t len) const {
    auto start = reinterpret_cast<uintptr_t>(buf);
    auto end = reinterpret_cast<uintptr_t>(start + len);
    return end >= start && start >= base_ && end <= base_ + len_;
  }

  [[nodiscard]] const void *get_base() const {
    return reinterpret_cast<void *>(base_);
  }

  [[nodiscard]] size_t get_mem_usage() const {
    uintptr_t size = 0;
    for (auto const &e : vmareas_) {
      size += e.second.end - e.second.start;
    }
    return reinterpret_cast<size_t>(size);
  }

  // Remove existing VMAreas that overlap with the range [start, end)
  // Ex: ClearMapping(2, 6) when vmareas_ = [1, 3), [5, 7)
  // results in vmareas_ = [1, 2), [6, 7).
  void ClearMapping(uintptr_t start, uintptr_t end) {
    // We want the first interval [a,b] where b > start (first overlap)
    auto cur = vmareas_.upper_bound(start);

    while (cur != vmareas_.end()) {
      VMArea &cur_vma = cur->second;
      uintptr_t cur_start = cur_vma.start;
      uintptr_t cur_end = cur_vma.end;

      if (end <= cur_start) break;
      // If we're here we know there's an overlap

      // [start, end) does not overlap on the left of [cur_start, cur_end).
      // Shorten cur_vma to [cur_start, start).
      if (start > cur_start) {
        VMArea vma = cur_vma;
        vma.end = start;
        vmareas_[start] = vma;
        cur++;
      }

      // [start, end) either overlaps on the right or surrounds [cur_start,
      // cur_end). Either way cur_end is being overwritten so remove it.
      if (end >= cur_end)
        cur = vmareas_.erase(cur);
      else {
        // [start, end) either overlaps on the left or is surrounded by
        // [cur_start, cur_end). Keep cur_end and shorten it to [end, cur_end).
        cur_vma.start = end;
        cur++;
      }
    }
  }

  void Insert(const VMArea &vma) {
    uintptr_t start = vma.start;
    uintptr_t end = vma.end;

    ClearMapping(start, end);
    vmareas_[end] = vma;
  }

 private:
  rt::Spin lock_;
  const uintptr_t base_;
  const size_t len_;
  uintptr_t brk_addr_;
  std::map<uintptr_t, VMArea> vmareas_;
};

// Reserve a region of virtual memory for a MemoryMap.
inline Status<std::shared_ptr<MemoryMap>> CreateMemoryMap(size_t len) {
  Status<void *> ret = KernelMMap(nullptr, len, PROT_NONE, 0);
  if (!ret) return MakeError(ret);
  return std::make_shared<MemoryMap>(*ret, len);
}

}  // namespace junction
