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
Status<jif_header> ReadHeader(JunctionFile &f) {
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
Status<std::vector<jif_phdr>> ReadPHDRs(JunctionFile &f,
                                        const jif_header &hdr) {
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
Status<std::vector<char>> ReadStrings(JunctionFile &f, const jif_header &hdr) {
  std::vector<char> strings(hdr.jif_strings_size);

  // Read the PHDRs into the vector.
  f.Seek(jif_strings_offset(hdr));
  Status<void> ret = ReadFull(f, std::as_writable_bytes(std::span(strings)));
  if (!ret) return MakeError(ret);

  return strings;
}

// ReadITrees reads the interval trees
Status<std::vector<jif_itree_node_t>> ReadITrees(JunctionFile &f,
                                                 const jif_header &hdr) {
  std::vector<jif_itree_node_t> itrees(hdr.jif_itrees_size /
                                       sizeof(jif_itree_node_t));

  // Read the PHDRs into the vector.
  f.Seek(jif_itrees_offset(hdr));
  Status<void> ret = ReadFull(f, std::as_writable_bytes(std::span(itrees)));
  if (!ret) return MakeError(ret);

  return itrees;
}

// ReadOrd reads the ord chunks
Status<std::vector<jif_ord_chunk_t>> ReadOrd(JunctionFile &f,
                                             const jif_header &hdr) {
  std::vector<jif_ord_chunk_t> ords(hdr.jif_ord_size / sizeof(jif_ord_chunk_t));

  // Read the PHDRs into the vector.
  f.Seek(jif_ord_offset(hdr));
  Status<void> ret = ReadFull(f, std::as_writable_bytes(std::span(ords)));
  if (!ret) return MakeError(ret);

  return ords;
}

// LoadOneSegment loads one loadable PHDR into memory
Status<void> LoadOneSegment(MemoryMap &mm, JunctionFile &f,
                            const jif_phdr &phdr) {
  // Determine the mapping permissions.
  unsigned int prot = 0;
  if (phdr.jifp_prot & kJIFFlagExec) prot |= PROT_EXEC;
  if (phdr.jifp_prot & kJIFFlagWrite) prot |= PROT_WRITE;
  if (phdr.jifp_prot & kJIFFlagRead) prot |= PROT_READ;

  // Determine the layout.
  // TODO(jif): this should be done by the kernel
  // size_t length = phdr.jifp_vend - phdr.jifp_vbegin;

  // Map the file part of the segment.
  // TODO(jif)

  return {};
}

// TODO(jif): this should call the kernel module
Status<jif_data> ParseJIF(JunctionFile &file) {
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

// TODO(jif): this should call the kernel module
Status<jif_data> LoadJIF(MemoryMap &mm, JunctionFile &jif_file) {
  auto jif = ParseJIF(jif_file);
  if (!jif) return MakeError(jif);

  // Load the segments.
  for (const jif_phdr &phdr : jif->jif_phdrs) {
    // TODO: unsure where this map_offset comes from
    Status<void> ret = LoadOneSegment(mm, jif_file, phdr);
    if (!ret) return MakeError(ret);
  }

  return {};
}
}  // namespace junction
