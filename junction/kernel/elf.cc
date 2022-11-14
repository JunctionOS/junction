#include "junction/kernel/elf.h"

#include <algorithm>
#include <bit>
#include <string>
#include <vector>

#include "junction/base/arch.h"
#include "junction/base/error.h"
#include "junction/base/io.h"
#include "junction/base/log.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"

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
  KETypeDynamic = 3,  // Dynamically loaded type
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
  auto str = string_view{hdr.magic, 4};
  if (str.compare("\177ELF") != 0) return false;
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
Status<elf_header> ReadHeader(int lfd) {
  elf_header hdr;
  KernelFileReader f(lfd);
  Status<void> ret = ReadFull(&f, writable_byte_view(hdr));
  if (!ret) MakeError(ret);
  if (!HeaderIsValid(hdr)) {
    LOG(ERR) << "elf: invalid/unsupported ELF file.";
    return MakeError(EINVAL);
  }
  return hdr;
}

// ReadPHDRs reads a vector of PHDRs from the ELF file
Status<std::vector<elf_phdr>> ReadPHDRs(int lfd, const elf_header &hdr) {
  std::vector<elf_phdr> phdrs(hdr.phnum);

  // Read the PHDRs into the vector.
  KernelFileReader f(lfd);
  f.Seek(hdr.phoff);
  Status<void> ret = ReadFull(&f, {phdrs.data(), hdr.phnum});
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
    if (phdr.type != PTypeLoad) continue;
    len = std::max(len, phdr.vaddr + phdr.memsz);
  }
  return len;
}

// ReadInterp loads the interpretor section and returns a path
Status<std::string> ReadInterp(int lfd, const elf_phdr &phdr) {
  std::string interp_path(phdr.filesz, '\0');
  KernelFileReader f(lfd);
  f.Seek(phdr.offset);
  Status<void> ret = ReadFull(&f, {interp_path.data(), phdr.filesz});
  if (!ret) MakeError(ret);
  return std::move(interp_path);
}

// ClearSegments unmaps all segments
void ClearSegments(off_t map_off, const std::vector<elf_phdr> &phdrs) {
  for (const elf_phdr &phdr : *phdrs) {
    sys_munmap(reinterpret_cast<void *>(phdr.vaddr + map_off), phdr.memsz);
  }
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
  uintptr_t start = page_align_down(pdhr.vaddr + map_off);
  uintptr_t file_end = pdhr.vaddr + map_off + phdr.filesz;
  uintptr_t gap_end = page_align(file_end);
  uintptr_t mem_end = pdhr.vaddr + map_off + phdr.memsz;

  // Map the file part of the segment.
  if (file_end > start) {
    Status<void> ret =
        f.MMapFixed(reinterpret_case<void *>(start), file_end - start, prot,
                    MAP_DENYWRITE, page_align_down(phdr.offset));
    if (unlikely(!ret)) return MakeError(ret);
  }

  // Map the remaining anonymous part of the segment.
  if (mem_end > gap_end) {
    Status<void> ret = MMapFixed(reinterpret_cast<void *>(gap_end),
                                 mem_end - gap_end, prot, MAP_DENYWRITE);
    if (unlikely(!ret)) return MakeError(ret);
  }

  return {};
}

// LoadSegments loads all loadable PHDRs
Status<void> LoadSegments(KernelFile &f, const std::vector<elf_phdr> &phdrs,
                          bool reloc) {
  // Determine the base address.
  off_t map_off = 0;
  if (reloc) {
    size_t len = CountTotalLength(phdrs);
    Status<void *> ret = MMap(len, PROT_NONE, 0);
    if (!ret) return MakeError(ret);
    map_off = static_cast<off_t>(*ret);
  }

  // Load the segments.
  for (const elf_phdr &phdr : *phdrs) {
    if (phdr.type != kPTypeLoad) continue;
    Status<void> ret = LoadOneSegment(lfd, map_off, phdr);
    if (!ret) return MakeError(ret);
  }

  return {};
}

Status<elf_data::interp_data> LoadInterp(const std::string &path) {}

}  // namespace

namespace junction {

// Loads an ELF file into the address space. Returns the entry address.
Status<elf_data> LoadELF(int lfd) {
  // Load the ELF header.
  Status<elf_header> hdr = ReadHeader(lfd);
  if (!hdr) {
    LOG(ERR) << "elf: couldn't load ELF file header.";
    return MakeError(hdr);
  }

  // Check if the ELF type is supported.
  if (hdr->type != kETypeExec && hdr->type != kETypeDynamic) {
    LOG(ERR) << "elf: unsupported ELF type '" << hdr->type << "'.";
    return MakeError(EINVAL);
  }

  // Load the PHDR table.
  Status<std::vector<elf_phdr>> phdrs = ReadPHDRs(lfd, *hdr);
  if (!phdrs) {
    LOG(ERR) << "elf: couldn't load ELF PHDR table.";
    return MakeError(phdrs);
  }

  // Load the interpreter if one is requested.
  for (const elf_phdr &phdr : *phdrs) {
    if (phdr.type == kPTypeInterp) {
      Status<std::string> path = ReadInterp(phdr);
      if (!path) MakeError(path);
      Status<elf_data::interp_data> ret = LoadInterp();
      if (!ret) MakeError(ret);
      break;
    }
  }

  // Success, return entry address.
  return hdr.entry;
}

}  // namespace junction
