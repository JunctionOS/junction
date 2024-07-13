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

std::ostream &operator<<(std::ostream &os, const jif_phdr &phdr) {
  phdr.Print(os);
  return os;
}

std::ostream &operator<<(std::ostream &os, const jif_interval_t &ival) {
  os << "[" << std::hex << ival.start << ", " << std::hex << ival.end
     << "]: " << (long)ival.offset;
  return os;
}

std::ostream &operator<<(std::ostream &os, const jif_itree_node_t &node) {
  os << "Node {";
  for (auto &ival : node.ranges)
    if (ival.IsValid()) os << ival << ", ";
  os << "};";
  return os;
}

namespace {

constexpr bool HeaderIsValid(const jif_header &hdr) {
  return hdr.jif_magic[0] == 0x77 && hdr.jif_magic[1] == 'J' &&
         hdr.jif_magic[2] == 'I' && hdr.jif_magic[3] == 'F';
}

// ReadHeader reads and validates the header of the JIF file
Status<jif_header> ReadHeader(KernelFile &f) {
  jif_header hdr;
  Status<void> ret = ReadFull(f, writable_byte_view(hdr));
  if (unlikely(!ret)) return MakeError(ret);
  if (unlikely(!HeaderIsValid(hdr))) {
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
  if (unlikely(!ret)) return MakeError(ret);

  // Confirm that the PHDRs contain valid state.
  // TODO: make this an assert so it runs in debug mode only.
  for (const jif_phdr &phdr : phdrs) BUG_ON(!phdr.is_valid());
  return phdrs;
}

// ReadStrings reads the strings
Status<std::vector<char>> ReadStrings(KernelFile &f, const jif_header &hdr) {
  std::vector<char> strings(hdr.jif_strings_size);

  // Read the PHDRs into the vector.
  f.Seek(jif_strings_offset(hdr));
  Status<void> ret = ReadFull(f, std::as_writable_bytes(std::span(strings)));
  if (unlikely(!ret)) return MakeError(ret);

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
  if (unlikely(!ret)) return MakeError(ret);

  return itrees;
}

// ReadOrd reads the ord chunks
Status<std::vector<jif_ord_chunk_t>> ReadOrd(KernelFile &f,
                                             const jif_header &hdr) {
  std::vector<jif_ord_chunk_t> ords(hdr.jif_ord_size / sizeof(jif_ord_chunk_t));

  // Read the PHDRs into the vector.
  f.Seek(jif_ord_offset(hdr));
  Status<void> ret = ReadFull(f, std::as_writable_bytes(std::span(ords)));
  if (unlikely(!ret)) return MakeError(ret);

  return ords;
}

[[nodiscard]] bool ITreeValidAux(std::span<const jif_itree_node_t> tree,
                                 size_t node_idx, uint64_t min, uint64_t max) {
  // base case
  if (node_idx >= tree.size()) return true;

  size_t child_idx = node_idx * FANOUT + 1;

  for (auto &ival : tree[node_idx].ranges) {
    // Check subtree
    if (!ITreeValidAux(tree, child_idx++, min, ival.start)) return false;

    // Check this interval
    if (ival.start < min || ival.end > max) return false;

    // Update minimum allowed value
    min = ival.end;
  }

  // Right child
  return ITreeValidAux(tree, child_idx, min, max);
}

// in-order traversal of the tree, checking that the construction is valid.
[[nodiscard]] bool ITreeValid(std::span<const jif_itree_node_t> tree) {
  return ITreeValidAux(tree, 0, 0, kUInt64Max);
}

// Load a pheader
Status<void> LoadPhdr(const jif_data &jif, KernelFile &jif_file,
                      const jif_phdr &phdr) {
  // Determine the mapping permissions.
  unsigned int prot = 0;
  if (phdr.jifp_prot & kJIFFlagExec) prot |= PROT_EXEC;
  if (phdr.jifp_prot & kJIFFlagWrite) prot |= PROT_WRITE;
  if (phdr.jifp_prot & kJIFFlagRead) prot |= PROT_READ;

  Status<void> ret;

  // Map the backing region, either a file or anonymous memory.
  if (phdr.HasRefFile()) {
    // Open reference file
    const char *ptr = jif.jif_strings.data() + phdr.jifp_pathname_offset;
    Status<KernelFile> ref_file = KernelFile::Open(ptr, 0, FileMode::kRead);
    if (unlikely(!ref_file)) {
      LOG(ERR) << "failed to open reference file `" << ptr
               << "` for pheader [0x" << std::hex << phdr.jifp_vbegin << "; 0x"
               << phdr.jifp_vend << "): " << ref_file.error().ToString();
      return MakeError(ref_file);
    }
    ret = ref_file->MMapFixed(phdr.Ptr(), phdr.Len(), prot, 0, phdr.Off());
  } else {
    ret = KernelMMapFixed(phdr.Ptr(), phdr.Len(), prot, 0);
  }

  if (unlikely(!ret)) {
    LOG(ERR) << "Failed to map phdr backing data";
    return ret;
  }

  if (phdr.jifp_itree_n_nodes == 0) return {};

  std::span<const jif_itree_node_t> full_itree{jif.jif_itrees};
  std::span<const jif_itree_node_t> phdr_itree =
      full_itree.subspan(phdr.jifp_itree_idx, phdr.jifp_itree_n_nodes);

  assert(ITreeValid(phdr_itree));

  // Overlay intervals on top of the backing region.
  for (const auto &node : phdr_itree) {
    for (const auto &ival : node.ranges) {
      if (!ival.IsValid()) continue;
      if (ival.HasOffset())
        ret = jif_file.MMapFixed(ival.Ptr(), ival.Len(), prot, 0, ival.Off());
      else
        ret = KernelMMapFixed(ival.Ptr(), ival.Len(), prot, 0);
      if (unlikely(!ret)) return ret;
    }
  }

  return {};
}

Status<jif_data> ParseJIF(KernelFile &file) {
  // Load the JIF header.
  Status<jif_header> hdr = ReadHeader(file);
  if (unlikely(!hdr)) return MakeError(hdr);

  // Load the PHDR table.
  Status<std::vector<jif_phdr>> phdrs = ReadPHDRs(file, *hdr);
  if (unlikely(!phdrs)) return MakeError(phdrs);

  // Load the String table.
  Status<std::vector<char>> strings = ReadStrings(file, *hdr);
  if (unlikely(!strings)) return MakeError(strings);

  // Load the Itrees table.
  Status<std::vector<jif_itree_node_t>> itrees = ReadITrees(file, *hdr);
  if (unlikely(!itrees)) return MakeError(itrees);

  // Load the Ord table.
  Status<std::vector<jif_ord_chunk_t>> ords = ReadOrd(file, *hdr);
  if (unlikely(!ords)) return MakeError(ords);

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
  if (unlikely(!jif)) return MakeError(jif);

  // Load the segments.
  for (const jif_phdr &phdr : jif->jif_phdrs) {
    Status<void> ret = LoadPhdr(*jif, jif_file, phdr);
    if (unlikely(!ret)) return MakeError(ret);
  }

  return {};
}
}  // namespace junction
