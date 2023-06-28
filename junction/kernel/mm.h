// mm.h - memory mapping support

#pragma once

#include <memory>

#include "junction/base/arch.h"
#include "junction/base/error.h"
#include "junction/bindings/sync.h"
#include "junction/kernel/ksys.h"

namespace junction {

class alignas(kCacheLineSize) MemoryMap {
 public:
  MemoryMap(void *base, size_t len)
      : base_(reinterpret_cast<uintptr_t>(base)),
        len_(len),
        brk_addr_(base_),
        map_addr_(base_ + len_) {}
  ~MemoryMap() { KernelMUnmap(reinterpret_cast<void *>(base_), len_); }

  // Sets the break address (for the heap), or returns prior address if
  // invalid.
  uintptr_t SetBreak(uintptr_t addr) {
    if (addr < base_) return brk_addr_;
    rt::SpinGuard g(lock_);
    if (addr > map_addr_) return brk_addr_;
    brk_addr_ = addr;
    return addr;
  }

  // Gets the break address (for the heap).
  [[nodiscard]] uintptr_t GetBreak() const { return brk_addr_; }

  // Reserve space for a memory mapping. Returns nullptr if no space available.
  void *ReserveForMapping(size_t len) {
    len = PageAlign(len);
    rt::SpinGuard g(lock_);
    if (map_addr_ - len < brk_addr_) return nullptr;
    map_addr_ -= len;
    return reinterpret_cast<void *>(map_addr_);
  }

  // Give back memory to be mapped again.
  // TODO(amb): this is hacky, maybe we need a vmarea thing instead.
  void ReturnForMapping(void *base, size_t len) {
    auto pos = reinterpret_cast<uintptr_t>(base);
    if (pos != PageAlign(pos) || len != PageAlign(len)) return;
    rt::SpinGuard g(lock_);
    if (pos == map_addr_) map_addr_ += len;
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

 private:
  rt::Spin lock_;
  const uintptr_t base_;
  const size_t len_;
  uintptr_t brk_addr_;
  uintptr_t map_addr_;
};

// Reserve a region of virtual memory for a MemoryMap.
inline Status<std::shared_ptr<MemoryMap>> CreateMemoryMap(size_t len) {
  Status<void *> ret = KernelMMap(len, PROT_NONE, 0);
  if (!ret) return MakeError(ret);
  return std::make_shared<MemoryMap>(*ret, len);
}

}  // namespace junction
