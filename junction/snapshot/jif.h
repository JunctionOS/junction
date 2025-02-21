// jif.h - JIF object file loader

#pragma once

#include <optional>
#include <string_view>

#include "junction/base/error.h"
#include "junction/fs/fs.h"
#include "junction/kernel/mm.h"

namespace junction {

constexpr size_t kJifMagicLen = 4;
constexpr uint32_t kJifVersion = 4;

// program header format
struct jif_phdr {
  // start virtual address of the vma (page aligned)
  uint64_t vbegin;
  // end virtual address of the vma (page aligned)
  uint64_t vend;

  // start offset in the reference file where the segment is (page aligned)
  // == -1 if the segment has no ref file
  uint64_t ref_offset;

  // offset into index tree table;
  // must be valid (i.e., < len)
  uint32_t itree_idx;
  // size of the itree in nodes; may be 0
  uint32_t itree_n_nodes;

  // offset into the strings table;
  // == -1 if the segment has no ref file
  uint32_t pathname_offset;

  // VMA protections
  uint8_t prot;

  [[nodiscard]] bool HasRefFile() const { return ref_offset != kUInt64Max; }
  [[nodiscard]] size_t Len() const { return vend - vbegin; }
  [[nodiscard]] void *Ptr() const { return reinterpret_cast<void *>(vbegin); }
  [[nodiscard]] off_t Off() const {
    assert(HasRefFile());
    return static_cast<off_t>(ref_offset);
  }

  void Print(std::ostream &os) const {
    os << std::hex << vbegin << "-" << std::hex << vend << " "
       << static_cast<long>(ref_offset);
  }

  [[nodiscard]] bool is_valid() const {
    if (!IsPageAligned(vbegin) || !IsPageAligned(vend)) return false;
    if (vbegin > vend) return false;
    if (HasRefFile()) {
      if (!IsPageAligned(ref_offset)) return false;
      if (pathname_offset == kUInt32Max) return false;
    }
    return true;
  }
} __packed;

struct jif_header {
  // used to detect the file type (expect 0x77 'J' 'I' 'F')
  uint8_t magic[kJifMagicLen];
  // number of pheaders
  uint32_t n_pheaders;
  // size of the strings section in B (page aligned)
  uint32_t strings_size;
  // size of the interval tree section in B (page aligned)
  uint32_t itrees_size;
  // size of the ordering section in B (page aligned)
  uint32_t ord_size;
  // JIF version.
  uint32_t version;
  // Number of pages that were written to from data section to prefetch.
  uint64_t n_write_prefetch;
  // Number of pages from data section to prefetch.
  uint64_t n_total_prefetch;

  // absolute offset of the pheader table
  [[nodiscard]] constexpr uint64_t pheader_offset() const {
    return sizeof(jif_header);
  }
  // absolute offset of the strings table
  [[nodiscard]] uint64_t strings_offset() const {
    return PageAlign(pheader_offset() + n_pheaders * sizeof(jif_phdr));
  }
  // absolute offset of the itrees table
  [[nodiscard]] uint64_t itrees_offset() const {
    return strings_offset() + strings_size;
  }
  // absolute offset of the ord table
  [[nodiscard]] uint64_t ord_offset() const {
    return itrees_offset() + itrees_size;
  }
  // absolute offset of the data section
  [[nodiscard]] uint64_t data_offset() const { return ord_offset() + ord_size; }
} __packed;

inline constexpr size_t FANOUT = 4;

struct jif_interval_t {
  uint64_t start;   // virtual addr; == -1 if this is not a valid interval
  uint64_t end;     // virtual addr; == -1 if this i not a valid interval
  uint64_t offset;  // offset into JIF; == -1 if this is a zero segment
  [[nodiscard]] bool IsValid() const {
    assert(start != kUInt64Max || end == kUInt64Max);
    return start != kUInt64Max;
  }
  [[nodiscard]] bool HasOffset() const { return offset != kUInt64Max; }
  [[nodiscard]] size_t Len() const {
    assert(IsValid());
    return end - start;
  }
  [[nodiscard]] void *Ptr() const {
    assert(IsValid());
    return reinterpret_cast<void *>(start);
  }
  [[nodiscard]] off_t Off() const {
    assert(HasOffset());
    return static_cast<off_t>(offset);
  }
} __packed;

struct jif_itree_node_t {
  std::array<jif_interval_t, FANOUT - 1> ranges;
  void InitEmpty() { memset(this, 0xff, sizeof(*this)); }
} __packed;

struct jif_ord_chunk_t {
  uint64_t timestamp_us;
  uint64_t vaddr;
  uint64_t n_pages;
} __packed;

std::ostream &operator<<(std::ostream &os, const jif_phdr &phdr);
std::ostream &operator<<(std::ostream &os, const jif_interval_t &ival);
std::ostream &operator<<(std::ostream &os, const jif_itree_node_t &node);

struct IOVAccumulator;

struct jif_data {
  jif_header hdr;
  std::vector<jif_phdr> phdrs;
  std::vector<char> strings;
  std::vector<jif_itree_node_t> itrees;
  std::vector<jif_ord_chunk_t> ord;
  Status<void> AddPhdr(IOVAccumulator &iovs, uint8_t prot, uintptr_t start,
                       size_t filesz, size_t memsz, size_t ref_offset,
                       std::string_view name);
};

namespace {}  // anonymous namespace

// TODO: make JIF use the same bits as the Linux kernel.
enum {
  kJIFFlagExec = 1,   // Executable permission
  kJIFFlagWrite = 2,  // Write permission
  kJIFFlagRead = 4,   // Read permission
};

inline constexpr int JIFProtToLinuxProt(int jprot) {
  int lprot = 0;
  if (jprot & kJIFFlagExec) lprot |= PROT_EXEC;
  if (jprot & kJIFFlagWrite) lprot |= PROT_WRITE;
  if (jprot & kJIFFlagRead) lprot |= PROT_READ;
  return lprot;
}

inline constexpr int LinuxProtToJIFProt(int lprot) {
  int jprot = 0;
  if (lprot & PROT_EXEC) jprot |= kJIFFlagExec;
  if (lprot & PROT_WRITE) jprot |= kJIFFlagWrite;
  if (lprot & PROT_READ) jprot |= kJIFFlagRead;
  return jprot;
}

// Load an JIF object file into memory
Status<jif_data> LoadJIF(KernelFile &jif_file);

}  // namespace junction
