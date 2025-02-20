// mm.h - memory mapping support

#pragma once

#include <atomic>
#include <memory>
#include <vector>

#include "junction/base/arch.h"
#include "junction/base/error.h"
#include "junction/base/interval_set.h"
#include "junction/bindings/log.h"
#include "junction/bindings/sync.h"
#include "junction/fs/file.h"
#include "junction/kernel/ksys.h"
#include "junction/snapshot/cereal.h"

namespace junction {

class MemoryMap;
class Process;

inline constexpr uintptr_t kVirtualAreaMax = 0x500000000000;

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

  size_t DataLength() const {
    if (type != VMType::kFile) return Length();
    return std::min(PageAlign(file->get_size() - offset), Length());
  }

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

  [[nodiscard]] uintptr_t get_start() const { return start; }
  [[nodiscard]] uintptr_t get_end() const { return end; }

  void TrimTail(uintptr_t new_end) {
    assert(end > new_end);
    end = new_end;
  }

  void TrimHead(uintptr_t new_start) {
    assert(start < new_start);
    if (type == VMType::kFile) offset += new_start - start;
    start = new_start;
  }

  bool TryMergeRight(const VMArea &lhs);

  uintptr_t start;
  uintptr_t end;
  int prot;
  bool traced : 1 {false};
  VMType type;
  std::shared_ptr<File> file;
  off_t offset;

  template <class Archive>
  void serialize(Archive &ar) {
    ar(start, end, prot, type, file, offset);
  }
};

std::ostream &operator<<(std::ostream &os, const VMArea &vma);

class PageAccessTracer {
 public:
  PageAccessTracer() = default;

  // Record a new page being accessed
  // Updates the hit time to the earliest time if an existing hit exists.
  // Returns true if this was the first access.
  bool RecordHit(uintptr_t page, Time t, int fault_type) {
    assert(IsPageAligned(page));
    auto [it, inserted] = access_at_.try_emplace(page, t);
    it->second = std::min(it->second, t);
    if (fault_type == PROT_WRITE) {
      auto [it, inserted] = page_writes_.insert(page);
      return inserted;
    }
    return inserted;
  }

  const std::unordered_map<uintptr_t, Time> &get_trace() const {
    return access_at_;
  }

  void Dump(std::ostream &os) const {
    for (const auto &[page_addr, time] : access_at_)
      os << std::dec << time.Microseconds() << ": 0x" << std::hex << page_addr
         << "\n";
    size_t total = access_at_.size();
    size_t writes = page_writes_.size();
    os << "# Total accesses: " << std::dec << total << " writes: " << writes
       << " (" << (writes * 100) / total << "%)\n";
  }

 private:
  std::unordered_map<uintptr_t, Time> access_at_;
  std::unordered_set<uintptr_t> page_writes_;
};

inline std::ostream &operator<<(std::ostream &os,
                                const PageAccessTracer &tracer) {
  tracer.Dump(os);
  return os;
}

// MemoryMap manages memory for a process
class alignas(kCacheLineSize) MemoryMap {
 public:
  MemoryMap(void *base, size_t len)
      : mm_start_(reinterpret_cast<uintptr_t>(base)),
        mm_end_(mm_start_ + len),
        brk_addr_(mm_start_) {}
  ~MemoryMap();

  [[nodiscard]] std::vector<VMArea> get_vmas();

  // Run a function for each VMA. Runs with the memory map lock held (shared).
  template <typename F>
  void ForEachVMA(F func) {
    rt::ScopedSharedLock g(mu_);
    for (auto const &[end, vma] : vmareas_) func(vma);
  }

  void MarkAsFake() { is_fake_map_ = true; }

  // Free all VMAs from this memory map. Must be called by Exec when replacing
  // one non-reloc binary with another.
  void UnmapAll();

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

  bool ContainedInMapBounds(void *addr, size_t len) const;

  // LogMappings prints all the mappings to the log.
  void LogMappings();
  std::string GetMappingsString();

  // Start a tracer on this memory map. Sets all permissions in the kernel to
  // PROT_NONE and updates permissions when page faults occur. All threads must
  // be stopped.
  void EnableTracing(Process &p);

  // End tracing. All threads must be stopped or the process must be exiting.
  Status<PageAccessTracer> EndTracing();

  [[nodiscard]] Status<void> DumpTracerReport();

  bool RecordHit(void *addr, size_t len, Time t, int fault_type);

  [[nodiscard]] bool TraceEnabled() const { return !!tracer_; }

  [[nodiscard]] PageAccessTracer &get_tracer() {
    assert(TraceEnabled());
    return *tracer_.get();
  }

  // Returns true if this page fault is handled by the MM.
  bool HandlePageFault(uintptr_t addr, int required_prot, Time time);

  [[nodiscard]] std::string get_bin_path() const;
  [[nodiscard]] std::string get_bin_name() const;
  [[nodiscard]] std::string_view get_cmd_line() const { return cmd_line_; }

  [[nodiscard]] bool is_non_reloc() const { return is_non_reloc_; };

  void mark_non_reloc() {
    assert(!is_non_reloc_);
    is_non_reloc_ = true;
    nr_non_reloc_maps_++;
  };

  void set_bin_path(std::shared_ptr<DirectoryEntry> binary_path,
                    const std::vector<std::string_view> &argv) {
    binary_path_ = std::move(binary_path);
    size_t len = 0;
    for (auto &arg : argv) len += arg.size() + 1;
    cmd_line_.reserve(len);
    for (auto &arg : argv) {
      auto ptr = arg.data();
      cmd_line_.insert(cmd_line_.end(), ptr, ptr + arg.size() + 1);
    }
  }

  static void RegisterMMRegion(uintptr_t base, size_t len) {
    rt::SpinGuard g(mm_lock_);
    assert(!mem_areas_.has_overlap(base, base + len));
    mem_areas_.Insert({base, base + len});
  }

  [[nodiscard]] static size_t get_nr_non_reloc() { return nr_non_reloc_maps_; }

  static rt::Spin &global_lock() { return mm_lock_; };

  static Status<std::shared_ptr<MemoryMap>> Create(size_t len);

  // Returns the top of the stack that rsp is from if the corresponding VMA was
  // created with MAP_STACK.
  std::optional<void *> GetStackTop(uint64_t rsp) {
    rt::SharedMutexGuard g(mu_);
    auto vma_ref = Find(rsp);
    if (!vma_ref) return std::nullopt;
    const VMArea &vma = *vma_ref;
    if (vma.type == VMType::kStack) return vma.Addr();
    return std::nullopt;
  }

 private:
  friend class cereal::access;
  friend class PageAccessTracer;

  void save(cereal::BinaryOutputArchive &ar) const;
  static void load_and_construct(cereal::BinaryInputArchive &ar,
                                 cereal::construct<MemoryMap> &construct);

  static void FreeMMRegion(uintptr_t start, uintptr_t end) {
    rt::SpinGuard g(mm_lock_);
    mem_areas_.Clear(start, end);
  }

  static Status<uintptr_t> AllocateMMRegion(size_t len) {
    rt::SpinGuard g(mm_lock_);
    Status<uintptr_t> ret =
        mem_areas_.FindFreeRange(0, len, kVirtualAreaMax, 0);
    if (ret) mem_areas_.Insert({*ret, *ret + len});
    return ret;
  }

  // Clear removes existing VMAreas that overlap with the range [start, end)
  // Ex: ClearMappings(2, 6) when vmareas_ = [1, 3), [5, 7) results in vmareas_
  // = [1, 2), [6, 7). Returns an iterator to the first mapping after the
  // region that was cleared.
  std::map<uintptr_t, VMArea>::iterator Clear(uintptr_t start, uintptr_t end);

  // Find a VMA that contains addr.
  Status<std::reference_wrapper<VMArea>> Find(uintptr_t addr);

  // Modify changes the access protections for memory in the range [start,
  // end).
  void Modify(uintptr_t start, uintptr_t end, int prot);

  // Insert inserts a VMA, removing any overlapping mappings.
  void Insert(VMArea &&vma);

  // Must be called any time is region is being unmapped to potentially updated
  // the global mem_areas_ map.
  void MunmapCheck(void *addr, size_t len);

  rt::SharedMutex mu_;
  const uintptr_t mm_start_;
  const size_t mm_end_;
  uintptr_t brk_addr_;
  ExclusiveIntervalSet<VMArea> vmareas_;
  std::unique_ptr<PageAccessTracer> tracer_;
  std::shared_ptr<DirectoryEntry> binary_path_;
  std::string cmd_line_;
  bool is_non_reloc_{false};
  bool is_fake_map_{false};  // old ELF snapshot code uses this.
  static rt::Spin mm_lock_;
  static std::atomic_size_t nr_non_reloc_maps_;
  // Tracks all areas allocated in the virtual address space.
  static ExclusiveIntervalSet<SimpleInterval> mem_areas_;
};

}  // namespace junction
