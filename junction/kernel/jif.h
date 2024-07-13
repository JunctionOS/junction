// jif.h - JIF object file loader

#pragma once

#include <optional>
#include <string_view>

#include "junction/base/error.h"
#include "junction/fs/fs.h"
#include "junction/kernel/mm.h"

namespace junction {

constexpr size_t kJifMagicLen = 4;

struct jif_header {
  // used to detect the file type (expect 0x77 'J' 'I' 'F')
  uint8_t jif_magic[kJifMagicLen];
  // number of pheaders
  uint32_t jif_n_pheaders;
  // size of the strings section in B (page aligned)
  uint32_t jif_strings_size;
  // size of the interval tree section in B (page aligned)
  uint32_t jif_itrees_size;
  // size of the ordering section in B (page aligned)
  uint32_t jif_ord_size;
} __packed;

// program header format
struct jif_phdr {
  // start virtual address of the vma (page aligned)
  uint64_t jifp_vbegin;
  // end virtual address of the vma (page aligned)
  uint64_t jifp_vend;

  // start offset in the reference file where the segment is (page aligned)
  // == -1 if the segment has no ref file
  uint64_t jifp_ref_offset;

  // offset into index tree table;
  // must be valid (i.e., < len)
  uint32_t jifp_itree_idx;
  // size of the itree in nodes;
  // must be > 0
  uint32_t jifp_itree_n_nodes;

  // offset into the strings table;
  // == -1 if the segment has no ref file
  uint32_t jifp_pathname_offset;

  // VMA protections
  uint8_t jifp_prot;

  [[nodiscard]] bool HasRefFile() const {
    return jifp_ref_offset != kUInt64Max;
  }
  [[nodiscard]] size_t Len() const { return jifp_vend - jifp_vbegin; }
  [[nodiscard]] void *Ptr() const {
    return reinterpret_cast<void *>(jifp_vbegin);
  }
  [[nodiscard]] off_t Off() const {
    assert(HasRefFile());
    return static_cast<off_t>(jifp_ref_offset);
  }

  void Print(std::ostream &os) const {
    os << std::hex << jifp_vbegin << "-" << std::hex << jifp_vend << " "
       << static_cast<long>(jifp_ref_offset);
  }

  [[nodiscard]] bool is_valid() const {
    if (!IsPageAligned(jifp_vbegin) || !IsPageAligned(jifp_vend)) return false;
    if (jifp_vbegin > jifp_vend) return false;
    if (HasRefFile()) {
      if (!IsPageAligned(jifp_ref_offset)) return false;
      if (jifp_pathname_offset == kUInt32Max) return false;
    }
    return true;
  }
} __packed;

inline constexpr size_t FANOUT = 4;

struct jif_interval_t {
  uint64_t start;   // virtual addr; == -1 if this is not a valid interval
  uint64_t end;     // virtual addr; == -1 if this i not a valid interval
  uint64_t offset;  // offset into JIF; == -1 if this is a zero segment
  [[nodiscard]] bool IsValid() const { return start != kUInt64Max; }
  [[nodiscard]] bool HasOffset() const { return offset != kUInt64Max; }
  [[nodiscard]] size_t Len() const { return end - start; }
  [[nodiscard]] void *Ptr() const { return reinterpret_cast<void *>(start); }
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
  uint64_t vaddr;
  uint64_t n_pages;
} __packed;

std::ostream &operator<<(std::ostream &os, const jif_phdr &phdr);
std::ostream &operator<<(std::ostream &os, const jif_interval_t &ival);
std::ostream &operator<<(std::ostream &os, const jif_itree_node_t &node);

struct IOVAccumulator;

struct jif_data {
  jif_header jif_hdr;
  std::vector<jif_phdr> jif_phdrs;
  std::vector<char> jif_strings;
  std::vector<jif_itree_node_t> jif_itrees;
  std::vector<jif_ord_chunk_t> jif_ord;
  Status<void> AddPhdr(IOVAccumulator &iovs, uint8_t prot, uintptr_t start,
                       size_t filesz, size_t memsz, size_t ref_offset,
                       std::string_view name);
};

namespace {
// absolute offset of the pheader table
constexpr uint64_t jif_pheader_offset(const jif_header &hdr) {
  return sizeof(jif_header);
}
// absolute offset of the strings table
inline uint64_t jif_strings_offset(const jif_header &hdr) {
  return PageAlign(jif_pheader_offset(hdr) +
                   hdr.jif_n_pheaders * sizeof(jif_phdr));
}
// absolute offset of the itrees table
inline uint64_t jif_itrees_offset(const jif_header &hdr) {
  return jif_strings_offset(hdr) + hdr.jif_strings_size;
}
// absolute offset of the ord table
inline uint64_t jif_ord_offset(const jif_header &hdr) {
  return jif_itrees_offset(hdr) + hdr.jif_itrees_size;
}
// absolute offset of the data section
inline uint64_t jif_data_offset(const jif_header &hdr) {
  return jif_ord_offset(hdr) + hdr.jif_ord_size;
}
}  // anonymous namespace

enum {
  kJIFFlagExec = 1,   // Executable permission
  kJIFFlagWrite = 2,  // Write permission
  kJIFFlagRead = 4,   // Read permission
};

// Load an JIF object file into memory
Status<jif_data> LoadJIF(KernelFile &jif_file);

}  // namespace junction
