// mm.h - memory mapping support

#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include "junction/base/arch.h"
#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/bindings/sync.h"
#include "junction/fs/file.h"
#include "junction/kernel/ksys.h"
#include "junction/snapshot/cereal.h"

namespace junction {

class MemoryMap;

constexpr bool AddressValid(void *addr, size_t len) {
  // TODO(amb): maybe check if address is not in the Linux Kernel (negative)?
  return len > 0 && IsPageAligned(reinterpret_cast<uintptr_t>(addr));
}

enum class VMType : int {
  kNormal,  // mapping contains regular anonymous memory
  kHeap,    // mapping is part of the heap (allocated with brk())
  kStack,   // mapping is used as a stack
  kFile,    // mapping is backed by a file
};

// VMArea describes one mapping
struct VMArea {
  VMArea() = default;
  VMArea(void *addr, size_t len, int prot, VMType type)
      : start(reinterpret_cast<uintptr_t>(addr)),
        end(start + len),
        prot(prot),
        type(type) {}
  VMArea(void *addr, size_t len, int prot, std::shared_ptr<File> file,
         off_t offset)
      : start(reinterpret_cast<uintptr_t>(addr)),
        end(start + len),
        prot(prot),
        type(VMType::kFile),
        file(std::move(file)),
        offset(offset) {}

  // Addr returns a pointer to the base address of the VMA.
  void *Addr() const { return reinterpret_cast<void *>(start); }
  // Length returns the length of the VMA.
  size_t Length() const { return end - start; }

  std::string TypeString() const {
    switch (type) {
      case VMType::kNormal:
        return "";
      case VMType::kHeap:
        return "[heap]";
      case VMType::kStack:
        return "[stack]";
      case VMType::kFile:
        return file->get_filename();
      default:
        return "";
    }
  }

  std::string ProtString() const {
    std::string tmp("---p");
    if (prot & PROT_READ) tmp[0] = 'r';
    if (prot & PROT_WRITE) tmp[1] = 'w';
    if (prot & PROT_EXEC) tmp[2] = 'x';
    return tmp;
  }

  uintptr_t start;
  uintptr_t end;
  int prot;
  bool traced : 1 {false};
  VMType type;
  std::shared_ptr<File> file;
  off_t offset;
};

std::ostream &operator<<(std::ostream &os, const VMArea &vma);

struct TracerReport {
  TracerReport() = default;
  explicit TracerReport(
      std::vector<std::tuple<uint64_t, uintptr_t, std::string>> &&accesses,
      uint64_t total, uint64_t non_zero)
      : accesses_us(std::move(accesses)),
        total_pages(total),
        non_zero_pages(non_zero) {}

  std::vector<std::tuple<uint64_t, uintptr_t, std::string>> accesses_us;
  uint64_t total_pages{0};
  uint64_t non_zero_pages{0};
};

class PageAccessTracer {
 public:
  PageAccessTracer() = default;

  bool RecordHit(uintptr_t page, Time t) {
    assert(IsPageAligned(page));
    auto [it, inserted] = access_at_.try_emplace(page, t);
    it->second = std::min(it->second, t);
    return inserted;
  }

  void RecordBytes(uintptr_t page, size_t bytes) {
    non_zero_bytes_[page] = bytes;
  }

  TracerReport GenerateReport(MemoryMap &mm) const;

 private:
  friend class MemoryMap;
  std::unordered_map<uintptr_t, Time> access_at_;
  std::unordered_map<uintptr_t, uint64_t> non_zero_bytes_;
};

// MemoryMap manages memory for a process
class alignas(kCacheLineSize) MemoryMap {
 public:
  MemoryMap(void *base, size_t len)
      : mm_start_(reinterpret_cast<uintptr_t>(base)),
        mm_end_(mm_start_ + len),
        brk_addr_(mm_start_) {}
  ~MemoryMap();

  [[nodiscard]] std::vector<VMArea> get_vmas();

  // SetBreak sets the break address (for the heap). It returns the new address
  // on success, the old address on failure, or EINTR if interrupted.
  Status<uintptr_t> SetBreak(uintptr_t brk_addr);

  // MMap inserts a memory mapping.
  Status<void *> MMap(void *addr, size_t len, int prot, int flags,
                      std::shared_ptr<File> f, off_t off);

  // MMapAnonymous inserts an anonymous memory mapping.
  Status<void *> MMapAnonymous(void *addr, size_t len, int prot, int flags) {
    return MMap(addr, len, prot, flags | MAP_PRIVATE | MAP_ANONYMOUS, {}, 0);
  }

  // MProtect changes the access protections of a range of mappings.
  Status<void> MProtect(void *addr, size_t len, int prot);

  // MUnmap removes a range of mappings.
  Status<void> MUnmap(void *addr, size_t len);

  // MAdvise gives the kernel a hint about how a range of mappings will be used.
  Status<void> MAdvise(void *addr, size_t len, int hint);

  // VirtualUsage returns the size (in bytes) of allocated virtual memory.
  [[nodiscard]] size_t VirtualUsage();

  // HeapUsage returns the size (in bytes) of the heap.
  [[nodiscard]] size_t HeapUsage() const { return brk_addr_ - mm_start_; }

  // break_addr
  [[nodiscard]] size_t get_brk_addr() const { return brk_addr_; }

  // LogMappings prints all the mappings to the log.
  void LogMappings();

  // Start a tracer on this memory map. Sets all permissions in the kernel to
  // PROT_NONE and updates permissions when page faults occur.
  void EnableTracing();

  Status<TracerReport> EndTracing();

  [[nodiscard]] bool TraceEnabled() const { return !!tracer_; }

  // Returns true if this page fault is handled by the MM.
  bool HandlePageFault(uintptr_t addr, Time time);

  [[nodiscard]] std::string_view get_bin_path() const { return binary_path_; }

  [[nodiscard]] std::string_view get_cmd_line() const { return cmd_line_; }

  void set_bin_path(const std::string_view &path,
                    std::vector<std::string_view> &argv) {
    binary_path_ = std::string(path);
    size_t len = 0;
    for (auto &arg : argv) len += arg.size() + 1;
    cmd_line_.reserve(len);
    for (auto &arg : argv) {
      auto ptr = arg.data();
      cmd_line_.insert(cmd_line_.end(), ptr, ptr + arg.size() + 1);
    }
  }

  static uintptr_t AllocateMMRegion(size_t len) {
    rt::SpinGuard g(mm_lock_);
    uintptr_t base = mm_base_addr_;
    mm_base_addr_ += PageAlign(len);
    return base;
  }

  static void RegisterMMRegion(uintptr_t base, size_t len) {
    rt::SpinGuard g(mm_lock_);
    mm_base_addr_ = std::max(mm_base_addr_, base + PageAlign(len));
  }

 private:
  friend class cereal::access;
  friend class PageAccessTracer;
  template <class Archive>
  void save(Archive &ar) const {
    ar(mm_start_, mm_end_ - mm_start_, brk_addr_, binary_path_, cmd_line_);
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<MemoryMap> &construct) {
    uintptr_t mm_start, len;
    ar(mm_start, len);

    RegisterMMRegion(mm_start, len);

    Status<void *> ret =
        KernelMMap(reinterpret_cast<void *>(mm_start), len, PROT_NONE, 0);
    if (!ret) throw std::bad_alloc();

    construct(*ret, len);
    ar(construct->brk_addr_, construct->binary_path_, construct->cmd_line_);
  }

  // Find a free range of memory of size @len, returns the start address of that
  // range.
  Status<uintptr_t> FindFreeRange(void *hint, size_t len);

  // Clear removes existing VMAreas that overlap with the range [start, end)
  // Ex: ClearMappings(2, 6) when vmareas_ = [1, 3), [5, 7) results in vmareas_
  // = [1, 2), [6, 7). Returns an iterator to the first mapping after the
  // region that was cleared.
  std::map<uintptr_t, VMArea>::iterator Clear(uintptr_t start, uintptr_t end);

  // Find a VMA that contains addr.
  std::map<uintptr_t, VMArea>::iterator Find(uintptr_t addr);

  // Modify changes the access protections for memory in the range [start,
  // end).
  void Modify(uintptr_t start, uintptr_t end, int prot);

  // Insert inserts a VMA, removing any overlapping mappings.
  void Insert(VMArea &&vma);

  // Tries to merge two adjacent VMAs, erasing @prev if merge succeeds.
  bool TryMergeRight(std::map<uintptr_t, VMArea>::iterator prev, VMArea &rhs);

  rt::SharedMutex mu_;
  const uintptr_t mm_start_;
  const size_t mm_end_;
  uintptr_t brk_addr_;
  std::map<uintptr_t, VMArea> vmareas_;
  std::unique_ptr<PageAccessTracer> tracer_;
  std::string binary_path_;
  std::string cmd_line_;

  static rt::Spin mm_lock_;
  static uintptr_t mm_base_addr_;
};

// Reserve a region of virtual memory for a MemoryMap.
inline Status<std::shared_ptr<MemoryMap>> CreateMemoryMap(size_t len) {
  uintptr_t base = MemoryMap::AllocateMMRegion(len);
  Status<void *> ret =
      KernelMMap(reinterpret_cast<void *>(base), len, PROT_NONE, 0);
  if (!ret) return MakeError(ret);
  return std::make_shared<MemoryMap>(*ret, len);
}

}  // namespace junction
