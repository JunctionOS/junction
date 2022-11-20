#include "junction/kernel/elf.h"

#include <algorithm>
#include <bit>
#include <string>
#include <vector>

#include "junction/base/arch.h"
#include "junction/base/error.h"
#include "junction/base/io.h"
#include "junction/bindings/log.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"

namespace junction {
namespace {

constexpr size_t kMagicLen = 16;

struct elf_header {
  uint8_t magic[kMagicLen];  // used to detect the file type
  uint16_t type;             // the type of ELF file
  uint16_t machine;          // the machine's architecture
  uint32_t version;          // the object file version
  uint64_t entry;            // the entry point (a virtual address)
  uint64_t phoff;            // program header table offset (start location)
  uint64_t shoff;            // section header table offset (start location)
  uint32_t flags;            // processor-specific flags (ignored)
  uint16_t ehsize;           // ELF header size in bytes
  uint16_t phsize;           // size of a program header entry in bytes
  uint16_t phnum;            // number of program header entries
  uint16_t shsize;           // size of a section header entry in bytes
  uint16_t shnum;            // number of section header entries
  uint16_t shstrndx;         // section header string table index
};

// Magic values for just the file type we can support (X86_64 CPUs).
constexpr uint8_t kMagicClass64 = 2;    // 64-bit object file
constexpr uint8_t kMagicData2LSB = 1;   // 2's complement, little endian
constexpr uint8_t kMagicVersion = 1;    // the current ELF format version
constexpr uint16_t kMachineAMD64 = 62;  // X86_64 processor (Intel and AMD)

enum {
  kETypeExec = 2,     // Executable type
  kETypeDynamic = 3,  // Dynamically loaded type
  // other types are not supported
};

// program header format
struct elf_phdr {
  uint32_t type;    // the type of PHDR header
  uint32_t flags;   // permission flags
  uint64_t offset;  // the offset in the file that contains the data
  uint64_t vaddr;   // the target virtual address
  uint64_t paddr;   // can be ignored
  uint64_t filesz;  // size in bytes stored in the backing file
  uint64_t memsz;   // size in bytes in memory (can be larger than filesz)
  uint64_t align;   // the alignment; must be power of 2. offset and vaddr must
                    // be the same value modulo the alignment.
};

enum {
  kPTypeNull = 0,       // entry is unused
  kPTypeLoad = 1,       // segment that should be loaded
  kPTypeDynamic = 2,    // dynamic linker information
  kPTypeInterp = 3,     // contains a path to the interpreter to load
  kPTypeNote = 4,       // auxiliary information
  kPTypeSharedLib = 5,  // not used
  kPTypeSelf = 6,       // entry for the PHDR header table itself
  kPTypeTLS = 7,        // thread local storage segment
  // several more architecture-specific types are omitted for now
};

enum {
  kFlagExec = 1,   // Executable permission
  kFlagWrite = 2,  // Write permission
  kFlagRead = 4,   // Read permission
};

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
Status<elf_header> ReadHeader(KernelFile &f) {
  elf_header hdr;
  Status<void> ret = ReadFull(&f, writable_byte_view(hdr));
  if (!ret) MakeError(ret);
  if (!HeaderIsValid(hdr)) {
    LOG(ERR) << "elf: invalid/unsupported ELF file.";
    return MakeError(EINVAL);
  }
  return hdr;
}

// ReadPHDRs reads a vector of PHDRs from the ELF file
Status<std::vector<elf_phdr>> ReadPHDRs(KernelFile &f, const elf_header &hdr) {
  std::vector<elf_phdr> phdrs(hdr.phnum);

  // Read the PHDRs into the vector.
  f.Seek(hdr.phoff);
  Status<void> ret = ReadFull(&f, std::as_writable_bytes(std::span(phdrs)));
  if (!ret) MakeError(ret);

  // Confirm that the PHDRs contain valid state.
  for (const elf_phdr &phdr : phdrs) {
    if (!std::has_single_bit(phdr.align) || phdr.filesz > phdr.memsz ||
        (phdr.vaddr & (phdr.align - 1)) != (phdr.offset & (phdr.align - 1))) {
      LOG(ERR) << "elf: encountered an invalid PHDR.";
      return MakeError(EINVAL);
    }
  }
  return std::move(phdrs);
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
Status<std::string> ReadInterp(KernelFile &f, const elf_phdr &phdr) {
  std::string interp_path(phdr.filesz - 1,
                          '\0');  // Don't read the null terminator
  f.Seek(phdr.offset);
  Status<void> ret =
      ReadFull(&f, std::as_writable_bytes(std::span(interp_path)));
  if (!ret) MakeError(ret);
  return std::move(interp_path);
}

// LoadOneSegment loads one loadable PHDR into memory
Status<void> LoadOneSegment(KernelFile &f, off_t map_off,
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
        f.MMapFixed(reinterpret_cast<void *>(start), file_end - start, prot,
                    MAP_DENYWRITE, PageAlignDown(phdr.offset));
    if (unlikely(!ret)) return MakeError(ret);
  }

  // Zero the gap
  if (gap_end > file_end) {
    if ((prot & PROT_WRITE) == 0) {
      Status<void> ret =
          KernelMProtect(reinterpret_cast<void *>(PageAlignDown(file_end)),
                         kPageSize, prot | PROT_WRITE);
      if (unlikely(!ret)) return MakeError(ret);
    }
    memset(reinterpret_cast<void *>(file_end), 0, gap_end - file_end);
    if ((prot & PROT_WRITE) == 0) {
      Status<void> ret = KernelMProtect(
          reinterpret_cast<void *>(PageAlignDown(file_end)), kPageSize, prot);
      if (unlikely(!ret)) return MakeError(ret);
    }
  }

  // Map the remaining anonymous part of the segment.
  if (mem_end > gap_end) {
    Status<void> ret = KernelMMapFixed(reinterpret_cast<void *>(gap_end),
                                       mem_end - gap_end, prot, 0);
    if (unlikely(!ret)) return MakeError(ret);
  }

  return {};
}

// LoadSegments loads all loadable PHDRs
Status<std::tuple<uintptr_t, size_t>> LoadSegments(
    KernelFile &f, const std::vector<elf_phdr> &phdrs, bool reloc) {
  // Determine the base address.
  off_t map_off = 0;
  size_t map_len = CountTotalLength(phdrs);
  if (reloc) {
    Status<void *> ret = KernelMMap(map_len, PROT_NONE, 0);
    if (!ret) return MakeError(ret);
    map_off = reinterpret_cast<off_t>(*ret);
  }

  // Load the segments.
  for (const elf_phdr &phdr : phdrs) {
    if (phdr.type != kPTypeLoad) continue;
    Status<void> ret = LoadOneSegment(f, map_off, phdr);
    if (!ret) return MakeError(ret);
  }

  return std::make_tuple(map_off, map_len);
}

Status<elf_data::interp_data> LoadInterp(std::string_view path) {
  DLOG(INFO) << "elf: loading interpreter ELF object file '" << path << "'";

  // Open the file.
  Status<KernelFile> file = KernelFile::Open(path, 0, S_IRUSR | S_IXUSR);
  if (!file) return MakeError(file);

  // Load the ELF header.
  Status<elf_header> hdr = ReadHeader(*file);
  if (!hdr) return MakeError(hdr);

  // Check if the ELF type is supported.
  if (hdr->type != kETypeDynamic) return MakeError(EINVAL);

  // Load the PHDR table.
  Status<std::vector<elf_phdr>> phdrs = ReadPHDRs(*file, *hdr);
  if (!phdrs) return MakeError(phdrs);

  // Load the PHDR segments.
  Status<std::tuple<uintptr_t, size_t>> ret = LoadSegments(*file, *phdrs, true);
  if (!ret) return MakeError(ret);

  LOG(INFO) << "gdb: add-symbol-file " << path << " -o " << std::get<0>(*ret);

  // Success, return metadata.
  return elf_data::interp_data{.map_base{std::get<0>(*ret)},
                               .map_len{std::get<1>(*ret)},
                               .entry_addr{hdr->entry + std::get<0>(*ret)}};
}

}  // namespace

Status<elf_data> LoadELF(std::string_view path) {
  DLOG(INFO) << "elf: loading ELF object file '" << path << "'";

  // Open the file.
  Status<KernelFile> file = KernelFile::Open(path, 0, S_IRUSR | S_IXUSR);
  if (!file) return MakeError(file);

  // Load the ELF header.
  Status<elf_header> hdr = ReadHeader(*file);
  if (!hdr) return MakeError(hdr);

  // Check if the ELF type is supported.
  if (hdr->type != kETypeExec && hdr->type != kETypeDynamic) {
    return MakeError(EINVAL);
  }

  // Load the PHDR table.
  Status<std::vector<elf_phdr>> phdrs = ReadPHDRs(*file, *hdr);
  if (!phdrs) return MakeError(phdrs);

  // Load the interpreter (if present).
  std::optional<elf_data::interp_data> interp_data;
  for (const elf_phdr &phdr : *phdrs) {
    if (phdr.type != kPTypeInterp) continue;
    Status<std::string> path = ReadInterp(*file, phdr);
    if (!path) return MakeError(path);
    Status<elf_data::interp_data> data = LoadInterp(*path);
    if (!data) return MakeError(data);
    interp_data = *data;
    break;
  }

  // Load the PHDR segments.
  Status<std::tuple<uintptr_t, size_t>> ret =
      LoadSegments(*file, *phdrs, hdr->type == kETypeDynamic);
  if (!ret) return MakeError(ret);

  // Look for a PHDR table segment
  uintptr_t phdr_va = 0;
  for (const auto &phdr : *phdrs) {
    if (phdr.type != kPTypeSelf) continue;
    phdr_va = phdr.vaddr + std::get<0>(*ret);
    break;
  }

  LOG(INFO) << "gdb: add-symbol-file " << path << " -o " << std::get<0>(*ret);

  // Success, return metadata.
  return elf_data{.map_base{std::get<0>(*ret)},
                  .map_len{std::get<1>(*ret)},
                  .entry_addr{hdr->entry + std::get<0>(*ret)},
                  .phdr_addr{phdr_va},
                  .phdr_num{hdr->phnum},
                  .phdr_entsz{hdr->phsize},
                  .interp{std::move(interp_data)}};
}

}  // namespace junction