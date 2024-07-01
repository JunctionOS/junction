#include <cstdio>
#include <fstream>
#include <iostream>
#include <utility>

extern "C" {
#include <fcntl.h>
#include <signal.h>
}

#include "junction/base/error.h"
#include "junction/base/finally.h"
#include "junction/fs/file.h"
#include "junction/fs/junction_file.h"
#include "junction/fs/memfs/memfs.h"
#include "junction/kernel/elf.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/snapshot/cereal.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

namespace {

Status<std::pair<std::vector<elf_phdr>, std::vector<iovec>>> GetPHDRs(
    MemoryMap &mm, SnapshotContext &ctx) {
  const std::vector<VMArea> vmas = mm.get_vmas();
  std::vector<elf_phdr> phdrs;
  std::vector<iovec> iovs;
  size_t total_sections = vmas.size() + ctx.mem_areas_.size();
  phdrs.reserve(total_sections);
  iovs.reserve(total_sections);
  uint64_t offset = total_sections * sizeof(elf_phdr) + sizeof(elf_header);
  offset = AlignUp(offset, kPageSize);

  for (const VMArea &vma : vmas) {
    uint32_t flags = 0;
    if (vma.prot & PROT_EXEC) flags |= kFlagExec;
    if (vma.prot & PROT_WRITE) flags |= kFlagWrite;
    if (vma.prot & PROT_READ) flags |= kFlagRead;

    size_t filesz = vma.Length();
    if (vma.type == VMType::kFile)
      filesz = std::min(PageAlign(vma.file->get_size() - vma.offset), filesz);

    elf_phdr phdr = {
        .type = kPTypeLoad,
        .flags = flags,
        .offset = offset,
        .vaddr = vma.start,
        .paddr = 0,             // don't care
        .filesz = filesz,       // size of data in the file
        .memsz = vma.Length(),  // total memory region size
        .align = kPageSize,     // align to page size
    };
    phdrs.push_back(phdr);
    offset += filesz;

    if (!filesz) continue;

    // Make memory area readable if needed.
    if (!(vma.prot & PROT_READ)) {
      auto ret = KernelMProtect(reinterpret_cast<void *>(vma.start), filesz,
                                vma.prot | PROT_READ);
      if (!ret) return MakeError(ret);
    }

    iovs.emplace_back(reinterpret_cast<void *>(vma.start), filesz);
  }

  for (const FSMemoryArea &area : ctx.mem_areas_) {
    elf_phdr phdr = {
        .type = kPTypeLoad,
        .flags = kFlagRead | kFlagWrite,
        .offset = offset,
        .vaddr = reinterpret_cast<uintptr_t>(area.ptr),
        .paddr = 0,                  // don't care
        .filesz = area.in_use_size,  // size of data in the file
        .memsz = area.max_size,      // total memory region size
        .align = kPageSize,          // align to page size
    };
    phdrs.push_back(phdr);
    offset += area.in_use_size;
    if (area.in_use_size) iovs.emplace_back(area.ptr, area.in_use_size);
  }

  return std::make_pair(phdrs, iovs);
}

Status<void> SnapshotElf(MemoryMap &mm, SnapshotContext &ctx,
                         std::string_view elf_path) {
  auto ret = GetPHDRs(mm, ctx);
  if (!ret) return MakeError(ret);
  auto &[pheaders, iovs] = *ret;
  Status<KernelFile> elf_file =
      KernelFile::Open(elf_path, O_CREAT | O_TRUNC, FileMode::kWrite, 0644);

  if (unlikely(!elf_file)) return MakeError(elf_file);

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
  hdr.entry = 0;
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
  size_t header_size = sizeof(elf_header) + pheaders.size() * sizeof(elf_phdr);
  size_t padding = PageAlign(header_size) - header_size;
  elf_iovecs.reserve(2 * pheaders.size() + 2);

  elf_iovecs.emplace_back(&hdr, sizeof(elf_header));
  for (auto &pheader : pheaders)
    elf_iovecs.emplace_back(&pheader, sizeof(elf_phdr));

  std::unique_ptr<char[]> zeros;
  if (padding) {
    zeros.reset(new char[padding]);
    memset(zeros.get(), 0, padding);
    elf_iovecs.emplace_back(zeros.get(), padding);
  }

  elf_iovecs.insert(elf_iovecs.end(), iovs.begin(), iovs.end());
  return WritevFull(*elf_file, elf_iovecs);
}

Status<void> SnapshotMetadata(Process &p, std::string_view metadata_path) {
  if (Status<void> ret = FSSnapshotPrepare(); !ret) return ret;

  rt::RuntimeLibcGuard guard;

  Status<KernelFile> metadata_file = KernelFile::Open(
      metadata_path, O_CREAT | O_TRUNC, FileMode::kWrite, 0644);
  if (!metadata_file) return MakeError(metadata_file);
  StreamBufferWriter<KernelFile> w(*metadata_file);
  std::ostream outstream(&w);
  cereal::BinaryOutputArchive ar(outstream);
  ar(p.shared_from_this());
  return {};
}

}  // namespace

static std::unique_ptr<SnapshotContext> cur_context;

SnapshotContext &GetSnapshotContext() {
  if (unlikely(!cur_context)) throw std::runtime_error("not doing a snapshot");
  return *cur_context.get();
}

void StartSnapshotContext() {
  assert(!cur_context);
  cur_context.reset(new SnapshotContext);
}

void EndSnapshotContext() {
  assert(cur_context);
  cur_context.release();
}

Status<void> SnapshotProc(Process *p, std::string_view metadata_path,
                          std::string_view elf_path) {
  LOG(INFO) << "snapshotting proc " << p->get_pid() << " into " << metadata_path
            << " and " << elf_path;

  StartSnapshotContext();
  auto f = finally([] { EndSnapshotContext(); });
  Status<void> ret = SnapshotMetadata(*p, metadata_path);
  if (!ret) return ret;
  return SnapshotElf(p->get_mem_map(), GetSnapshotContext(), elf_path);
}

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

  auto f = finally([&] { p->Signal(SIGCONT); });
  return SnapshotProc(p.get(), metadata_path, elf_path);
}

Status<std::shared_ptr<Process>> RestoreProcess(std::string_view metadata_path,
                                                std::string_view elf_path) {
  rt::RuntimeLibcGuard guard;

  Time start = Time::Now();

  Status<KernelFile> f = KernelFile::Open(metadata_path, 0, FileMode::kRead);
  if (unlikely(!f)) return MakeError(f);
  StreamBufferReader<KernelFile> w(*f);
  std::istream instream(&w);
  cereal::BinaryInputArchive ar(instream);
  std::shared_ptr<Process> p;
  ar(p);

  Time end_metadata = Time::Now();

  Status<JunctionFile> elf =
      JunctionFile::Open(p->get_fs(), elf_path, 0, FileMode::kRead);
  if (unlikely(!elf)) return MakeError(elf);
  Status<elf_data> ret = LoadELF(p->get_mem_map(), *elf, p->get_fs(), elf_path);
  Time end_elf = Time::Now();
  if (unlikely(!ret)) {
    LOG(ERR) << "Elf load failed: " << ret.error();
    return MakeError(ret);
  };

  LOG(INFO) << "restore time " << (end_elf - start).Microseconds()
            << " metadata: " << (end_metadata - start).Microseconds()
            << " elf: " << (end_elf - end_metadata).Microseconds();

  // mark threads as runnable
  // (must be last things to run, this will get the snapshot running)
  p->RunThreads();
  return p;
}

}  // namespace junction
