#include <cstdio>

extern "C" {
#include <fcntl.h>
}

#include "junction/base/error.h"
#include "junction/kernel/file.h"
#include "junction/kernel/ksys.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

namespace {
std::vector<elf_phdr> GetPHDRs(std::vector<VMArea> &vmas) {
  std::vector<elf_phdr> phdrs;
  phdrs.reserve(vmas.size());
  uint64_t offset = vmas.size() * sizeof(elf_phdr) + sizeof(elf_header);
  offset = AlignUp(offset, kPageSize);

  for (const VMArea &vma : vmas) {
    uint32_t flags = 0;
    if (vma.prot & PROT_EXEC) flags |= kFlagExec;
    if (vma.prot & PROT_WRITE) flags |= kFlagWrite;
    if (vma.prot & PROT_READ) flags |= kFlagRead;
    elf_phdr phdr = {
        .type = kPTypeLoad,
        .flags = flags,
        .offset = offset,
        .vaddr = vma.start,
        .paddr = 0,              // don't care
        .filesz = vma.Length(),  // memory region size
        .memsz = vma.Length(),   // memory region size
        .align = kPageSize,      // align to page size
    };
    phdrs.push_back(phdr);
    offset += vma.Length();
  }

  return phdrs;
}
}  // namespace

void SnapshotMetadata(Process &p, std::string_view metadata_path) {
  // TODO(cereal): implement process snapshot
}

std::pair<std::shared_ptr<Process>, thread_tf> RestoreProcess(
    std::string_view metadata_path) {
  // TODO(cereal): actually implement code
  std::shared_ptr<Process> p;
  thread_tf trapframe;

  return std::make_pair(p, trapframe);
}

Status<void> SnapshotElf(std::vector<VMArea> vmas, uint64_t entry_addr,
                         std::string_view elf_path) {
  auto pheaders = GetPHDRs(vmas);
  auto elf_file = KernelFile::Open(elf_path, O_CREAT | O_TRUNC | O_WRONLY,
                                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

  if (unlikely(!elf_file)) {
    return MakeError(elf_file);
  }

  // write headers
  elf_header hdr;
  memset(&hdr, 0, sizeof(elf_header));
  hdr.magic[0] = '\177';
  hdr.magic[1] = 'E';
  hdr.magic[2] = 'L';
  hdr.magic[3] = 'F';
  hdr.magic[4] = kMagicClass64;
  hdr.magic[5] = kMagicData2LSB;
  hdr.magic[6] = kMagicVersion;
  hdr.type = kETypeExec;
  hdr.machine = kMachineAMD64;
  hdr.version = static_cast<uint32_t>(kMagicVersion);
  hdr.entry = entry_addr;
  hdr.phoff = sizeof(elf_header);
  hdr.shoff = 0;
  hdr.flags = 0;
  hdr.ehsize = sizeof(elf_header);
  hdr.phsize = sizeof(elf_phdr);
  hdr.phnum = pheaders.size();
  hdr.shsize = 0;
  hdr.shnum = 0;
  hdr.shstrndx = 0;

  std::vector<iovec> elf_iovecs;
  size_t const header_size =
      sizeof(elf_header) + pheaders.size() * sizeof(elf_phdr);
  bool const needs_padding = header_size < AlignUp(header_size, 4096);
  elf_iovecs.reserve(2 * pheaders.size() + 1 + (needs_padding) ? 1 : 0);

  std::array<std::byte, 4096> padding{std::byte{0}};
  iovec const iov = {.iov_base = reinterpret_cast<std::byte *>(&hdr),
                     .iov_len = sizeof(elf_header)};
  elf_iovecs.push_back(iov);
  for (auto &pheader : pheaders) {
    iovec const iov = {.iov_base = reinterpret_cast<std::byte *>(&pheader),
                       .iov_len = sizeof(elf_phdr)};
    elf_iovecs.push_back(iov);
  }

  if (needs_padding) {
    size_t padding_len = AlignUp(header_size, 4096) - header_size;
    iovec const iov = {.iov_base = padding.data(), .iov_len = padding_len};
    elf_iovecs.push_back(iov);
  }

  for (const VMArea &vma : vmas) {
    size_t mem_region_len = vma.Length();
    assert(IsPageAligned(mem_region_len));

    // TODO(amb): Copied this code but it looks incorrect
    // some regions are not readable so we need to remap them as readable
    // before they get written to the elf
    if (!(vma.prot & PROT_READ)) {
      auto ret = KernelMMapFixed(reinterpret_cast<void *>(vma.start),
                                 mem_region_len, vma.prot | PROT_READ, 0);
      if (!ret) return MakeError(ret);
    }
    iovec v = {.iov_base = reinterpret_cast<std::byte *>(vma.start),
               .iov_len = mem_region_len};
    elf_iovecs.push_back(v);
  }

  size_t expected_write_size = 0;
  for (auto const &vec : elf_iovecs) {
    expected_write_size += vec.iov_len;
  }
  auto const &ret = elf_file->Writev(elf_iovecs);
  if (unlikely(!ret)) {
    return MakeError(ret);
  } else if (*ret != expected_write_size) {
    return MakeError(-1);
  }
  return {};
}

}  // namespace junction
