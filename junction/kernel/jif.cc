#include "junction/kernel/jif.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <string>
#include <vector>

#include "junction/base/arch.h"
#include "junction/base/error.h"
#include "junction/base/io.h"
#include "junction/bindings/log.h"
#include "junction/fs/file.h"
#include "junction/fs/fs.h"
#include "junction/junction.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"

namespace junction {
namespace {

constexpr bool HeaderIsValid(const jif_header &hdr) {
  if (hdr.jif_magic[0] != 0x77 || hdr.jif_magic[1] != 'J' ||
      hdr.jif_magic[2] != 'I' || hdr.jif_magic[3] != 'F') {
    return false;
  }

  return true;
}

// ReadHeader reads and validates the header of the JIF file
Status<jif_header> ReadHeader(KernelFile &f) {
  jif_header hdr;
  Status<void> ret = ReadFull(f, writable_byte_view(hdr));
  if (!ret) return MakeError(ret);
  if (!HeaderIsValid(hdr)) {
    LOG(ERR) << "jif: invalid/unsupported JIF file.";
    return MakeError(EINVAL);
  }
  return hdr;
}

// ReadPHDRs reads a vector of PHDRs from the JIF file
Status<std::vector<jif_phdr>> ReadPHDRs(KernelFile &f, const jif_header &hdr) {
  std::vector<jif_phdr> phdrs(hdr.jif_n_pheaders);

  // Read the PHDRs into the vector.
  f.Seek(jif_pheader_offset(hdr));
  Status<void> ret = ReadFull(f, std::as_writable_bytes(std::span(phdrs)));
  if (!ret) return MakeError(ret);

  // Confirm that the PHDRs contain valid state.
  for (const jif_phdr &phdr : phdrs) {
    if (!phdr.is_valid()) {
      LOG(ERR) << "jif: encountered an invalid PHDR.";
      return MakeError(EINVAL);
    }
  }
  return phdrs;
}

// ReadStrings reads the strings
Status<std::vector<char>> ReadStrings(KernelFile &f, const jif_header &hdr) {
  std::vector<char> strings(hdr.jif_strings_size);

  // Read the PHDRs into the vector.
  f.Seek(jif_strings_offset(hdr));
  Status<void> ret = ReadFull(f, std::as_writable_bytes(std::span(strings)));
  if (!ret) return MakeError(ret);

  return strings;
}

// ReadITrees reads the interval trees
Status<std::vector<jif_itree_node_t>> ReadITrees(KernelFile &f,
                                                 const jif_header &hdr) {
  std::vector<jif_itree_node_t> itrees(hdr.jif_itrees_size /
                                       sizeof(jif_itree_node_t));

  // Read the interval trees into the vector.
  f.Seek(jif_itrees_offset(hdr));
  Status<void> ret = ReadFull(f, std::as_writable_bytes(std::span(itrees)));
  if (!ret) return MakeError(ret);

  return itrees;
}

// ReadOrd reads the ord chunks
Status<std::vector<jif_ord_chunk_t>> ReadOrd(KernelFile &f,
                                             const jif_header &hdr) {
  std::vector<jif_ord_chunk_t> ords(hdr.jif_ord_size / sizeof(jif_ord_chunk_t));

  // Read the PHDRs into the vector.
  f.Seek(jif_ord_offset(hdr));
  Status<void> ret = ReadFull(f, std::as_writable_bytes(std::span(ords)));
  if (!ret) return MakeError(ret);

  return ords;
}

Status<void> MapZero(uint64_t start, uint64_t end, uint8_t prot) {
  void *addr = reinterpret_cast<void *>(start);
  size_t len = end - start;
  auto ret = KernelMMapFixed(addr, len, prot, 0);
  if (!ret) return MakeError(ret);
  return {};
}

Status<void> MapData(uint64_t start, uint64_t end, KernelFile &jif_file,
                     uint64_t offset, uint8_t prot) {
  void *addr = reinterpret_cast<void *>(start);
  size_t len = end - start;
  auto ret = jif_file.MMapFixed(addr, len, prot, 0, offset);
  if (!ret) return MakeError(ret);
  return {};
}

Status<void> MapFile(uint64_t start, uint64_t end, KernelFile &ref_file,
                     off_t offset, uint8_t prot) {
  void *addr = reinterpret_cast<void *>(start);
  size_t len = end - start;
  auto ret = ref_file.MMapFixed(addr, len, prot, 0, offset);
  if (!ret) return MakeError(ret);
  return {};
}

// in-order traversal of the tree, checking for gaps or overlaps
bool CheckITree(const jif_phdr &phdr, std::span<const jif_itree_node_t> tree,
                size_t node_idx, uint64_t &last_end, bool allow_gaps) {
  // base case
  if (node_idx >= phdr.jifp_itree_n_nodes) return true;

  size_t child_idx = node_idx * FANOUT + 1;
  for (size_t i = 0; i < FANOUT - 1; i += 1, child_idx += 1) {
    // recursion
    auto ret = CheckITree(phdr, tree, child_idx, last_end, allow_gaps);
    if (!ret) return ret;

    jif_interval_t const *ival = &tree[node_idx].ranges[i];
    if (ival->start != static_cast<uint64_t>(-1)) {
      // valid interval

      if (!allow_gaps && last_end != ival->start) {
        // problem: there was a gap in the itree
        LOG(ERR) << "mapping error: needed an interval starting at 0x"
                 << std::hex << last_end << ", found one at 0x"
                 << ival->start;
        return false;
      }

      if (last_end > ival->start) {
        LOG(ERR) << "mapping error: overlap detected -- last mapping was at 0x"
                 << std::hex << last_end << ", next interval was [0x"
                 << ival->start << "; 0x" << ival->end << ")";
        return false;
      }

      if (ival->offset != static_cast<uint64_t>(-1) &&
          !IsPageAligned(ival->offset)) {
        // invalid offset
        LOG(ERR) << "mapping error: interval at [0x" << std::hex << ival->start
                 << "; 0x" << ival->end << ") has a non-page aligned offset: 0x"
                 << ival->offset;
      }

      last_end = ival->end;
    }
  }

  // right child
  return CheckITree(phdr, tree, child_idx, last_end, allow_gaps);
}

// map the nodes
Status<void> MapITree(KernelFile &jif_file, const jif_phdr &phdr, uint8_t prot,
                      std::span<const jif_itree_node_t> tree) {
  for (const auto &node : tree) {
    for (size_t i = 0; i < FANOUT - 1; i += 1) {
      jif_interval_t const *ival = &node.ranges[i];
      if (ival->start != static_cast<uint64_t>(-1)) {
        // valid interval

        if (ival->offset == static_cast<uint64_t>(-1)) {
          // zero interval
          auto ret = MapZero(ival->start, ival->end, prot);
          if (!ret) return ret;
        } else {
          // data interval
          auto ret =
              MapData(ival->start, ival->end, jif_file, ival->offset, prot);
          if (!ret) return ret;
        }
      }
    }
  }

  return {};
}

Status<void> LoadRefPhdr(const jif_data &jif, KernelFile &jif_file,
                         const jif_phdr &phdr, KernelFile &ref_file,
                         uint8_t prot) {
  // map the reference file
  auto map_file = MapFile(phdr.jifp_vbegin, phdr.jifp_vend, ref_file,
                          phdr.jifp_ref_offset, prot);
  if (!map_file) return map_file;

  // no itree means the full segment is file backed
  if (phdr.jifp_itree_n_nodes == 0) {
    return {};
  }

  std::span<const jif_itree_node_t> full_itree{jif.jif_itrees};
  std::span<const jif_itree_node_t> phdr_itree =
      full_itree.subspan(phdr.jifp_itree_idx, phdr.jifp_itree_n_nodes);

  uint64_t last_mapped = phdr.jifp_vbegin;
  if (!CheckITree(phdr, phdr_itree, 0, last_mapped, true /* allow gaps */)) {
    // invalid itree
    return MakeError(EINVAL);
  }

  return MapITree(jif_file, phdr, prot, phdr_itree);
}

Status<void> LoadAnonymousPhdr(const jif_data &jif, KernelFile &jif_file,
                               const jif_phdr &phdr, uint8_t prot) {
  if (phdr.jifp_itree_n_nodes == 0) {
    LOG(ERR) << "anonymous pheader [0x" << std::hex << phdr.jifp_vbegin
             << "; 0x" << phdr.jifp_vend
             << ") cannot be mapped without an interval tree";
    return MakeError(EINVAL);
  }

  std::span<const jif_itree_node_t> full_itree{jif.jif_itrees};
  std::span<const jif_itree_node_t> phdr_itree =
      full_itree.subspan(phdr.jifp_itree_idx, phdr.jifp_itree_n_nodes);

  uint64_t last_mapped = phdr.jifp_vbegin;
  if (!CheckITree(phdr, phdr_itree, 0, last_mapped, false /* allow gaps */) ||
      last_mapped != phdr.jifp_vend) {
    // invalid itree
    return MakeError(EINVAL);
  }

  return MapITree(jif_file, phdr, prot, phdr_itree);
}

// Load a pheader
Status<void> LoadPhdr(const jif_data &jif, KernelFile &jif_file,
                      const jif_phdr &phdr) {
  // Determine the mapping permissions.
  unsigned int prot = 0;
  if (phdr.jifp_prot & kJIFFlagExec) prot |= PROT_EXEC;
  if (phdr.jifp_prot & kJIFFlagWrite) prot |= PROT_WRITE;
  if (phdr.jifp_prot & kJIFFlagRead) prot |= PROT_READ;

  if (phdr.jifp_pathname_offset < jif.jif_strings.size()) {
    // Open reference file
    const char *ptr = jif.jif_strings.data() + phdr.jifp_pathname_offset;
    size_t len =
        strnlen(ptr, jif.jif_strings.size() - phdr.jifp_pathname_offset);
    std::string_view path{ptr, len};
    Status<KernelFile> ref_file = KernelFile::Open(path, 0, FileMode::kRead);
    if (!ref_file) {
      LOG(ERR) << "failed to open reference file `" << path
               << "` for pheader [0x" << std::hex << phdr.jifp_vbegin << "; 0x"
               << phdr.jifp_vend << "): " << ref_file.error().ToString();
      return MakeError(ref_file);
    }

    return LoadRefPhdr(jif, jif_file, phdr, *ref_file, prot);
  }
  return LoadAnonymousPhdr(jif, jif_file, phdr, prot);
}

Status<jif_data> ParseJIF(KernelFile &file) {
  // Load the JIF header.
  Status<jif_header> hdr = ReadHeader(file);
  if (!hdr) return MakeError(hdr);

  // Load the PHDR table.
  Status<std::vector<jif_phdr>> phdrs = ReadPHDRs(file, *hdr);
  if (!phdrs) return MakeError(phdrs);

  // Load the String table.
  Status<std::vector<char>> strings = ReadStrings(file, *hdr);
  if (!strings) return MakeError(strings);

  // Load the Itrees table.
  Status<std::vector<jif_itree_node_t>> itrees = ReadITrees(file, *hdr);
  if (!itrees) return MakeError(itrees);

  // Load the Ord table.
  Status<std::vector<jif_ord_chunk_t>> ords = ReadOrd(file, *hdr);
  if (!ords) return MakeError(ords);

  // Success, return metadata.
  return jif_data{
      .jif_hdr = *hdr,
      .jif_phdrs = *phdrs,
      .jif_strings = *strings,
      .jif_itrees = *itrees,
      .jif_ord = *ords,
  };
}

}  // anonymous namespace

Status<jif_data> LoadJIF(KernelFile &jif_file) {
  auto jif = ParseJIF(jif_file);
  if (!jif) return MakeError(jif);

  // Load the segments.
  for (const jif_phdr &phdr : jif->jif_phdrs) {
    Status<void> ret = LoadPhdr(*jif, jif_file, phdr);
    if (!ret) return MakeError(ret);
  }

  return {};
}
}  // namespace junction
