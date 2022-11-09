#include <string>
#include <vector>

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

constexpr uint8_t kMagicClass64 = 2;    // 64-bit object file
constexpr uint8_t kMagicData2LSB = 1;   // 2's complement, little endian
constexpr uint8_t kMagicVersion = 1;    // the current ELF format version
constexpr uint16_t kMachineAMD64 = 62;  // X86_64 processor (Intel and AMD)

// mask of supported PHDR type values (other types can be ignored)
constexpr uint32_t kPTypeMask = 0xf;

enum {
  kPTypeNull = 0,       // entry is unused
  kPTypeLoad = 1,       // segment that should be loaded
  kPTypeDynamic = 2,    // dynamic linker information
  kPTypeInterp = 3,     // contains a path to the interpreter to load
  kPTypeNote = 4,       // auxiliary information
  kPTypeSharedLib = 5,  // not used
  kPTypeSelf = 6,       // entry for the PHDR header table itself
  kPTypeTLS = 7,        // thread local storage segment
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
    LOG(ERR) << "elf: Invalid/unsupported ELF file.";
    return MakeError(EINVAL);
  }
  return hdr;
}

// ReadPHDRs reads a vector of PHDRs from the ELF file
Status<std::vector<elf_phdr>> ReadPHDRs(int lfd, off_t offset, size_t count) {
  std::vector<elf_phdr> phdrs(count);
  KernelFileReader f(lfd);
  f.Seek(offset);
  Status<void> ret = ReadFull(&f, {phdrs.data(), count});
  if (!ret) MakeError(ret);
  return std::move(phdrs);
}

// ParseInterp loads the interpretor section and returns a path
Status<std::string> ReadInterp(int lfd, const elf_phdr &phdr) {
  std::string interp_path(phdr.filesz, '\0');
  KernelFileReader f(lfd);
  f.Seek(phdr.offset);
  Status<void> ret = ReadFull(&f, {interp_path.data(), phdr.filesz});
  if (!ret) MakeError(ret);
  return std::move(interp_path);
}

// LoadSegment initializes a LOAD PHDR in memory, reading it from the ELF file
Status<void> LoadSegment(Proc *p, int lfd, off_t off, const elf_phdr &phdr) {}

}  // namespace

namespace junction {

Status<void> LoadELF(Proc *p, int lfd) {}

}  // namespace junction
