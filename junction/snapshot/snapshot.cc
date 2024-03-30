#include <cstdio>
#include <fstream>
#include <iostream>
#include <utility>

extern "C" {
#include <fcntl.h>
#include <signal.h>
}

#include "junction/base/error.h"
#include "junction/fs/file.h"
#include "junction/kernel/elf.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/snapshot/cereal.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

namespace {
std::pair<std::vector<elf_phdr>, std::vector<VMArea>> GetPHDRs(MemoryMap &mm) {
  auto vmas = mm.get_vmas();
  std::vector<elf_phdr> phdrs;
  phdrs.reserve(vmas.size() + 1);  // vmas + unused heap
  uint64_t offset = (1 + vmas.size()) * sizeof(elf_phdr) + sizeof(elf_header);
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

  elf_phdr heap_phdr = {
      .type = kPTypeLoad,
      .flags = 0,  // PROT_NONE
      .offset = offset,
      .vaddr = mm.get_brk_addr(),
      .paddr = 0,                // don't care
      .filesz = 0,               // memory region size
      .memsz = mm.UnusedHeap(),  // memory region size
      .align = kPageSize,        // align to page size
  };
  phdrs.push_back(heap_phdr);

  return std::make_pair(phdrs, vmas);
}

Status<void> SnapshotElf(MemoryMap &mm, uint64_t entry_addr,
                         std::string_view elf_path) {
  auto [pheaders, vmas] = GetPHDRs(mm);
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
      auto ret = KernelMProtect(reinterpret_cast<void *>(vma.start),
                                mem_region_len, vma.prot | PROT_READ);
      if (!ret) return MakeError(ret);
    }
    iovec v = {.iov_base = reinterpret_cast<std::byte *>(vma.start),
               .iov_len = mem_region_len};
    elf_iovecs.push_back(v);
  }

  return WritevFull(*elf_file, elf_iovecs);
}

void SnapshotMetadata(Process &p, std::string_view metadata_path) {
  rt::RuntimeLibcGuard guard;

  Status<KernelFile> metadata_file =
      KernelFile::Open(metadata_path, O_CREAT | O_TRUNC | O_WRONLY,
                       S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  BUG_ON(!metadata_file);
  StreamBufferWriter<KernelFile> w(*metadata_file);
  std::ostream outstream(&w);
  cereal::BinaryOutputArchive ar(outstream);
  ar(p.shared_from_this());
}

}  // namespace

Status<void> SnapshotPid(pid_t pid, std::string_view metadata_path,
                         std::string_view elf_path) {
  std::shared_ptr<Process> p = Process::Find(pid);
  if (!p) {
    LOG(WARN) << "couldn't find proc with pid " << pid;
    return MakeError(ESRCH);
  }

  LOG(INFO) << "stopping proc with pid " << pid;

  // TODO(snapshot): child procs, if any exist, should also be stopped + waited.
  p->Signal(SIGSTOP);
  p->WaitForFullStop();

  LOG(INFO) << "snapshotting proc " << pid << " into " << metadata_path
            << " and " << elf_path;
  SnapshotMetadata(*p.get(), metadata_path);
  Status<void> ret =
      SnapshotElf(p->get_mem_map(), 0 /* entry_addr */, elf_path);

  p->Signal(SIGCONT);
  return ret;
}

std::shared_ptr<Process> RestoreProcess(std::string_view metadata_path,
                                        std::string_view elf_path) {
  rt::RuntimeLibcGuard guard;

  Status<KernelFile> f = KernelFile::Open(metadata_path, O_RDONLY, 0644);
  BUG_ON(!f);

  StreamBufferReader<KernelFile> w(*f);
  std::istream instream(&w);
  cereal::BinaryInputArchive ar(instream);

  std::shared_ptr<Process> p;
  ar(p);

  MemoryMap &mm = p->get_mem_map();
  auto ret = LoadELF(mm, elf_path, p->get_filesystem());
  if (!ret) {
    LOG(ERR) << "Elf load failed: " << ret.error();
    return {};
  };

  // mark threads as runnable
  // (must be last things to run, this will get the snapshot running)
  p->RunThreads();
  return p;
}

}  // namespace junction
