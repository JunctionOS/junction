// elf.h - ELF object file loader

#pragma once

#include <optional>
#include <string_view>

#include "junction/base/error.h"
#include "junction/fs/fs.h"
#include "junction/fs/junction_file.h"
#include "junction/kernel/mm.h"

namespace junction {

constexpr size_t kMagicLen = 16;

// Magic values for just the file type we can support (X86_64 CPUs).
constexpr uint8_t kMagicClass64 = 2;    // 64-bit object file
constexpr uint8_t kMagicData2LSB = 1;   // 2's complement, little endian
constexpr uint8_t kMagicVersion = 1;    // the current ELF format version
constexpr uint16_t kMachineAMD64 = 62;  // X86_64 processor (Intel and AMD)

// elf_data contains metadata about a succesfully loaded ELF file.
struct elf_data {
  struct interp_data {
    uintptr_t map_base;    // the interpreter's mapped base address
    size_t map_len;        // the interpreter's length of its mapping
    uintptr_t entry_addr;  // the interpreter's entry address
  };

  uintptr_t map_base;    // the mapped base address
  size_t map_len;        // the length of the mapping
  uintptr_t entry_addr;  // the program's entry address
  uintptr_t phdr_addr;   // the program's PHDR table address
  size_t phdr_num;       // the number of PHDR entries in the table
  size_t phdr_entsz;     // the size of each PHDR entry

  // optional interpreter data (set if intrepeter is in use)
  std::optional<interp_data> interp;
};

#pragma pack(push, 1)
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
#pragma pack(pop)

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

enum : uint32_t {
  kPTypeNull = 0,       // entry is unused
  kPTypeLoad = 1,       // segment that should be loaded
  kPTypeDynamic = 2,    // dynamic linker information
  kPTypeInterp = 3,     // contains a path to the interpreter to load
  kPTypeNote = 4,       // auxiliary information
  kPTypeSharedLib = 5,  // not used
  kPTypeSelf = 6,       // entry for the PHDR header table itself
  kPTypeTLS = 7,        // thread local storage segment

  // values between LowOS and HighOS (inclusive) are reserved for OS specific
  // semantics
  kPTypeLowOS = 0x60000000,
  kPTypeHighOS = 0x6fffffff,

  // values between LowProc and HighProc (inclusive) are reserved for OS
  // specific semantics
  kPTypeLowProc = 0x70000000,
  kPTypeHighProc = 0x7fffffff,
};

enum {
  kFlagExec = 1,   // Executable permission
  kFlagWrite = 2,  // Write permission
  kFlagRead = 4,   // Read permission
};

// Check if file is a valid ELF file and can be loaded.
Status<void> CheckELFLoad(JunctionFile &file, elf_header &out,
                          bool must_be_reloc);

// Load an ELF file into memory (used after CheckELFLoad).
Status<elf_data> DoELFLoad(MemoryMap &mm, JunctionFile &file, FSRoot &fs,
                           const elf_header &hdr);

// Load an ELF object file into memory. Returns metadata if successful.
inline Status<elf_data> LoadELF(MemoryMap &mm, JunctionFile &file, FSRoot &fs) {
  elf_header hdr;
  Status<void> ret = CheckELFLoad(file, hdr, false);
  if (!ret) return MakeError(ret);
  return DoELFLoad(mm, file, fs, hdr);
}

}  // namespace junction
