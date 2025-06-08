#include "junction/kernel/elf.h"

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

constexpr bool HeaderIsValid(const elf_header &hdr) {
  if (hdr.magic[0] != '\177' || hdr.magic[1] != 'E' || hdr.magic[2] != 'L' ||
      hdr.magic[3] != 'F') {
    return false;
  }
  if (hdr.magic[4] != kMagicClass64) return false;
  if (hdr.magic[5] != kMagicData2LSB) return false;
  if (hdr.magic[6] != kMagicVersion) return false;
  if (hdr.version != static_cast<uint32_t>(kMagicVersion)) return false;
  if (hdr.machine != kMachineAMD64) return false;
  if (hdr.phsize != sizeof(elf_phdr)) return false;
  if (hdr.ehsize != sizeof(elf_header)) return false;
  return true;
}

// ReadHeader reads and validates the header of the ELF file
Status<void> ReadHeader(JunctionFile &f, elf_header &hdr) {
  Status<void> ret = ReadFull(f, writable_byte_view(hdr));
  if (ret && !HeaderIsValid(hdr)) {
    DLOG(DEBUG) << "elf: invalid/unsupported ELF file.";
    return MakeError(EINVAL);
  }
  return ret;
}

// ReadHeader reads and validates the header of the ELF file
Status<elf_header> ReadHeader(JunctionFile &f) {
  elf_header hdr;
  Status<void> ret = ReadHeader(f, hdr);
  if (!ret) return MakeError(ret);
  return hdr;
}

// ReadPHDRs reads a vector of PHDRs from the ELF file
Status<std::vector<elf_phdr>> ReadPHDRs(JunctionFile &f,
                                        const elf_header &hdr) {
  std::vector<elf_phdr> phdrs(hdr.phnum);

  // Read the PHDRs into the vector.
  f.Seek(hdr.phoff);
  Status<void> ret = ReadFull(f, std::as_writable_bytes(std::span(phdrs)));
  if (!ret) return MakeError(ret);

  // Confirm that the PHDRs contain valid state.
  for (const elf_phdr &phdr : phdrs) {
    if (phdr.filesz > phdr.memsz ||
        (phdr.align > 1 && (!std::has_single_bit(phdr.align) ||
                            (phdr.vaddr & (phdr.align - 1)) !=
                                (phdr.offset & (phdr.align - 1))))) {
      LOG(ERR) << "elf: encountered an invalid PHDR. " << phdr.align << " "
               << phdr.vaddr << " " << phdr.offset;
      return MakeError(EINVAL);
    }
  }
  return phdrs;
}

// CountTotalSize returns the size of all the segments together
size_t CountTotalLength(const std::vector<elf_phdr> &phdrs) {
  size_t len = 0;
  for (const elf_phdr &phdr : phdrs) {
    if (phdr.type != kPTypeLoad) continue;
    len = std::max(len, phdr.vaddr + phdr.memsz);
  }
  return len;
}

// ReadInterp loads the interpretor section and returns a path
Status<std::string> ReadInterp(JunctionFile &f, const elf_phdr &phdr) {
  std::string interp_path(phdr.filesz - 1,
                          '\0');  // Don't read the null terminator
  f.Seek(phdr.offset);
  Status<void> ret =
      ReadFull(f, std::as_writable_bytes(std::span(interp_path)));
  if (!ret) return MakeError(ret);
  return interp_path;
}

// LoadOneSegment loads one loadable PHDR into memory
Status<void> LoadOneSegment(MemoryMap &mm, JunctionFile &f, off_t map_off,
                            const elf_phdr &phdr) {
  // Determine the mapping permissions.
  unsigned int prot = 0;
  if (phdr.flags & kFlagExec) prot |= PROT_EXEC;
  if (phdr.flags & kFlagWrite) prot |= PROT_WRITE;
  if (phdr.flags & kFlagRead) prot |= PROT_READ;

  // Determine the layout.
  uintptr_t start = PageAlignDown(phdr.vaddr + map_off);
  uintptr_t file_end = phdr.vaddr + map_off + phdr.filesz;
  uintptr_t gap_end = PageAlign(file_end);
  uintptr_t mem_end = phdr.vaddr + map_off + phdr.memsz;

  // Map the file part of the segment.
  if (file_end > start) {
    Status<void> ret =
        f.MMapFixed(mm, reinterpret_cast<void *>(start), file_end - start, prot,
                    MAP_DENYWRITE, PageAlignDown(phdr.offset));
    if (unlikely(!ret)) return MakeError(ret);
  }

  // Zero the gap
  if (gap_end > file_end) {
    if ((prot & PROT_WRITE) == 0) {
      Status<void> ret =
          mm.MProtect(reinterpret_cast<void *>(PageAlignDown(file_end)),
                      kPageSize, prot | PROT_WRITE);
      if (unlikely(!ret)) return MakeError(ret);
    }
    std::memset(reinterpret_cast<void *>(file_end), 0, gap_end - file_end);
    if ((prot & PROT_WRITE) == 0) {
      Status<void> ret = mm.MProtect(
          reinterpret_cast<void *>(PageAlignDown(file_end)), kPageSize, prot);
      if (unlikely(!ret)) return MakeError(ret);
    }
  }

  // Map the remaining anonymous part of the segment.
  if (mem_end > gap_end) {
    Status<void *> ret = mm.MMapAnonymous(reinterpret_cast<void *>(gap_end),
                                          mem_end - gap_end, prot, MAP_FIXED);
    if (unlikely(!ret)) return MakeError(ret);
  }

  return {};
}

// LoadSegments loads all loadable PHDRs
Status<std::pair<uintptr_t, size_t>> LoadSegments(
    MemoryMap &mm, JunctionFile &f, const std::vector<elf_phdr> &phdrs,
    bool reloc) {
  // Determine the base address.
  off_t map_off = 0;
  size_t map_len = CountTotalLength(phdrs);
  if (reloc) {
    Status<void *> ret = mm.MMapAnonymous(nullptr, map_len, PROT_NONE, 0);
    if (unlikely(!ret)) return MakeError(ret);
    map_off = reinterpret_cast<off_t>(*ret);
  }

  // Load the segments.
  for (const elf_phdr &phdr : phdrs) {
    if (phdr.type != kPTypeLoad) continue;
    Status<void> ret = LoadOneSegment(mm, f, map_off, phdr);
    if (!ret) return MakeError(ret);
  }

  return std::make_pair(map_off, map_len);
}

// LoadInterp loads an interpreter binary (usually ld.so).
Status<elf_data::interp_data> LoadInterp(MemoryMap &mm, FSRoot &fs,
                                         std::string_view path) {
  if (junction::GetCfg().get_interp_path().size())
    path = junction::GetCfg().get_interp_path();

  DLOG(INFO) << "elf: loading interpreter ELF object file '" << path << "'";

  // Open the file.
  Status<JunctionFile> file = JunctionFile::Open(fs, path, 0, FileMode::kRead);
  if (!file) {
    LOG(ERR) << "exec: failed to find interpreter at " << path;
    return MakeError(file);
  }

  // Load the ELF header.
  Status<elf_header> hdr = ReadHeader(*file);
  if (!hdr) return MakeError(hdr);

  // Check if the ELF type is supported.
  if (hdr->type != kETypeDynamic) return MakeError(EINVAL);

  // Load the PHDR table.
  Status<std::vector<elf_phdr>> phdrs = ReadPHDRs(*file, *hdr);
  if (!phdrs) return MakeError(phdrs);

  // Load the PHDR segments.
  Status<std::pair<uintptr_t, size_t>> ret =
      LoadSegments(mm, *file, *phdrs, true);
  if (!ret) return MakeError(ret);

  DLOG(DEBUG) << "gdb: add-symbol-file " << path << " -o " << std::get<0>(*ret);

  // Success, return metadata.
  return elf_data::interp_data{.map_base{std::get<0>(*ret)},
                               .map_len{std::get<1>(*ret)},
                               .entry_addr{hdr->entry + std::get<0>(*ret)}};
}

// FindPHDRByType returns the first PHDR of a type if one exists.
std::optional<elf_phdr> FindPHDRByType(const std::vector<elf_phdr> &v,
                                       uint32_t type) {
  auto it = std::find_if(v.begin(), v.end(), [type](const elf_phdr &phdr) {
    return phdr.type == type;
  });
  if (it == v.end()) return {};
  return *it;
}

}  // namespace

Status<void> CheckELFLoad(JunctionFile &file, elf_header &out,
                          bool must_be_reloc) {
  // Load the ELF header.
  Status<void> ret = ReadHeader(file, out);
  if (ret) {
    bool reloc = out.type == kETypeDynamic;
    // Check if the ELF type is supported.
    if (out.type != kETypeExec && !reloc) return MakeError(EINVAL);
    if (!reloc && must_be_reloc) {
      LOG(ERR) << "Cannot load multiple non-relocatable binaries";
      return MakeError(EINVAL);
    }
  }
  return ret;
}

Status<elf_data> DoELFLoad(MemoryMap &mm, JunctionFile &file, FSRoot &fs,
                           const elf_header &hdr) {
  // Load the PHDR table.
  Status<std::vector<elf_phdr>> phdrs = ReadPHDRs(file, hdr);
  if (!phdrs) return MakeError(phdrs);

  // Load the interpreter (if present).
  std::optional<elf_data::interp_data> interp_data;
  std::optional<elf_phdr> phdr = FindPHDRByType(*phdrs, kPTypeInterp);
  if (phdr) {
    Status<std::string> path = ReadInterp(file, *phdr);
    if (!path) return MakeError(path);
    Status<elf_data::interp_data> data = LoadInterp(mm, fs, *path);
    if (!data) return MakeError(data);
    interp_data = *data;
  }

  bool reloc = hdr.type == kETypeDynamic;
  if (!reloc) mm.mark_non_reloc();

  // Load the PHDR segments.
  Status<std::pair<uintptr_t, size_t>> ret =
      LoadSegments(mm, file, *phdrs, reloc);
  if (!ret) return MakeError(ret);
  // Look for a PHDR table segment
  uintptr_t phdr_va = 0;
  phdr = FindPHDRByType(*phdrs, kPTypeSelf);
  if (!phdr) phdr = phdrs->front();
  phdr_va = phdr->vaddr + std::get<0>(*ret) + hdr.phoff - phdr->offset;

  // Success, return metadata.
  return elf_data{.map_base{std::get<0>(*ret)},
                  .map_len{std::get<1>(*ret)},
                  .entry_addr{hdr.entry + std::get<0>(*ret)},
                  .phdr_addr{phdr_va},
                  .phdr_num{hdr.phnum},
                  .phdr_entsz{hdr.phsize},
                  .interp{std::move(interp_data)}};
}

}  // namespace junction
