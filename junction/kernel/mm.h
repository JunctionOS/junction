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

struct elf_phdr;
class Snapshotter;
class ProcessMetadata;
class VMAreaMetadata;

enum class VMType : uint8_t {
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

  VMAreaMetadata Snapshot() const &;
};

class alignas(kCacheLineSize) MemoryMap {
 public:
  MemoryMap(void *base, size_t len)
      : base_(reinterpret_cast<uintptr_t>(base)), len_(len), brk_addr_(base_) {
    VMArea vma = {.start = base_,
                  .end = base_ + PageAlign(len_),
                  .offset = 0,
                  .prot = PROT_NONE,
                  .flags = MAP_ANONYMOUS | MAP_PRIVATE,
                  .file = nullptr,
                  .type = VMType::kHeap};
    vmareas_[vma.end] = vma;
  }
  MemoryMap(ProcessMetadata const &pm);
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
        .start = reinterpret_cast<uintptr_t>(*ret),
        .end = reinterpret_cast<uintptr_t>(*ret) + PageAlign(len),
        .offset = off,
        .prot = prot,
        .flags = flags,
        .file = f,
        .type = VMType::kFile,
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
        .start = reinterpret_cast<uintptr_t>(*ret),
        .end = reinterpret_cast<uintptr_t>(*ret) + PageAlign(len),
        .offset = 0,
        .prot = prot,
        .flags = flags,
        .file = nullptr,
        .type = type,
    };
    rt::SpinGuard g(lock_);
    Insert(vma);
    return ret;
  }

  void Snapshot(ProcessMetadata &s) const &;
  void Restore(ProcessMetadata const &pm, FileTable &ftbl);
  Status<size_t> SerializeMemoryRegions(Snapshotter &s) const &;
  std::vector<elf_phdr> GetPheaders(uint64_t starting_offset) const &;

  // Returns true if the mapping is inside the reserved region.
  bool IsWithin(void *buf, size_t len) const {
    auto start = reinterpret_cast<uintptr_t>(buf);
    auto end = reinterpret_cast<uintptr_t>(start + len);
    return end >= start && start >= base_ && end <= base_ + len_;
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
    size_t size = 0;
    for (auto const &[_ptr, vma] : vmareas_) {
      size += static_cast<size_t>(vma.end - vma.start);
    }
    return size;
  }

  [[nodiscard]] size_t get_n_vmareas() const { return vmareas_.size(); }

 private:
  // Apply func to each VMA in the range [start, end). func returns true if it
  // wishes to remove the current VMA. func may mutate vmareas_ directly.
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
