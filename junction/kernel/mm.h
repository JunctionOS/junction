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
    UpdateProtection(start, end, prot);
    return {};
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

 private:
  // Apply F to each VMA in the range [start, end). F returns true if it wishes
  // to remove the current VMA. F may mutate vmareas_ directly.
  template <typename F>
  void ForEachOverlap(uintptr_t start, uintptr_t end, F func);

  // Remove existing VMAreas that overlap with the range [start, end)
  // Ex: ClearMapping(2, 6) when vmareas_ = [1, 3), [5, 7)
  // results in vmareas_ = [1, 2), [6, 7).
  void ClearMapping(uintptr_t start, uintptr_t end);

  // Change the protection for memory in the range [start, end).
  void UpdateProtection(uintptr_t start, uintptr_t end, int prot);

  void Insert(const VMArea &vma) {
    assert(lock_.IsHeld());
    ClearMapping(vma.start, vma.end);
    vmareas_[vma.end] = vma;
  }

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
