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
#include "junction/net/unix.h"
#include "junction/snapshot/cereal.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

namespace {

// Writes a uint64 in little-endian to the writer.
Status<void> WriteU64LE(VectoredWriter &w, uint64_t v) {
  iovec iov = {&v, sizeof(v)};
  return WritevFull(w, {&iov, 1});
}

Status<void> WriteU8(VectoredWriter &w, uint8_t v) {
  iovec iov = {&v, sizeof(v)};
  return WritevFull(w, {&iov, 1});
}

Status<std::pair<std::vector<elf_phdr>, std::vector<iovec>>> GetElfPHDRs(
    MemoryMap &mm, SnapshotContext &ctx) {
  const std::vector<VMArea> vmas = mm.get_vmas();
  std::vector<elf_phdr> phdrs;
  std::vector<iovec> iovs;
  size_t total_sections = vmas.size() + ctx.mem_areas_.size();
  phdrs.reserve(total_sections);
  iovs.reserve(total_sections);
  uint64_t offset = total_sections * sizeof(elf_phdr) + sizeof(elf_header);
  offset = PageAlign(offset);

  for (const VMArea &vma : vmas) {
    uint32_t flags = 0;
    if (vma.prot & PROT_EXEC) flags |= kFlagExec;
    if (vma.prot & PROT_WRITE) flags |= kFlagWrite;
    if (vma.prot & PROT_READ) flags |= kFlagRead;

    size_t filesz = vma.DataLength();

    // Make memory area readable if needed.
    if (filesz && !(vma.prot & PROT_READ)) {
      auto ret = KernelMProtect(reinterpret_cast<void *>(vma.start), filesz,
                                vma.prot | PROT_READ);
      if (!ret) return MakeError(ret);
    }

    // Get rid of trailing zero pages.
    filesz = PageAlign(GetMinSize(reinterpret_cast<void *>(vma.start), filesz));

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

    if (filesz) {
      offset += filesz;
      iovs.emplace_back(reinterpret_cast<void *>(vma.start), filesz);
    }
  }

  for (const FSMemoryArea &area : ctx.mem_areas_) {
    size_t saved_area = PageAlign(GetMinSize(area.ptr, area.in_use_size));

    elf_phdr phdr = {
        .type = kPTypeLoad,
        .flags = kFlagRead | kFlagWrite,
        .offset = offset,
        .vaddr = reinterpret_cast<uintptr_t>(area.ptr),
        .paddr = 0,              // don't care
        .filesz = saved_area,    // size of data in the file
        .memsz = area.max_size,  // total memory region size
        .align = kPageSize,      // align to page size
    };
    phdrs.push_back(phdr);
    offset += saved_area;
    if (saved_area) iovs.emplace_back(area.ptr, saved_area);
  }

  return std::make_pair(phdrs, iovs);
}

// Builds the ELF iovec list (header + phdrs + padding + data) and writes it
// to the given writer, then restores VMA protections.
Status<void> WriteElfIovecs(MemoryMap &mm, SnapshotContext &ctx,
                            VectoredWriter &out) {
  auto ret = GetElfPHDRs(mm, ctx);
  if (!ret) return MakeError(ret);
  auto &[pheaders, iovs] = *ret;

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

  size_t header_size = sizeof(elf_header) + pheaders.size() * sizeof(elf_phdr);
  size_t padding = PageAlign(header_size) - header_size;
  std::array<std::byte, 4096> zeros{std::byte{0}};

  std::vector<iovec> elf_iovecs;
  elf_iovecs.reserve(pheaders.size() + iovs.size() + 2);
  elf_iovecs.emplace_back(&hdr, sizeof(elf_header));
  for (auto &pheader : pheaders)
    elf_iovecs.emplace_back(&pheader, sizeof(elf_phdr));
  if (padding > 0) elf_iovecs.emplace_back(zeros.data(), padding);
  elf_iovecs.insert(elf_iovecs.end(), iovs.begin(), iovs.end());

  if (Status<void> r = WritevFull(out, elf_iovecs); !r) return r;

  size_t elf_bytes = 0;
  for (const auto &iov : elf_iovecs) elf_bytes += iov.iov_len;
  LOG(INFO) << "migration: ELF bytes transferred: " << elf_bytes << " ("
            << (elf_bytes / 1024) << " KiB)";

  return RestoreVMAProtections(mm);
}

Status<void> SnapshotElf(MemoryMap &mm, SnapshotContext &ctx,
                         std::string_view elf_path) {
  Status<KernelFile> elf_file =
      KernelFile::Open(elf_path, O_CREAT | O_TRUNC, FileMode::kWrite, 0644);
  if (unlikely(!elf_file)) return MakeError(elf_file);
  return WriteElfIovecs(mm, ctx, *elf_file);
}

Status<void> SnapshotElfToStream(MemoryMap &mm, SnapshotContext &ctx,
                                 VectoredWriter &out) {
  return WriteElfIovecs(mm, ctx, out);
}

}  // namespace

Status<void> SnapshotProcToELF(Process *p, std::string_view metadata_path,
                               std::string_view elf_path) {
  LOG(INFO) << "snapshotting proc " << p->get_pid() << " into " << metadata_path
            << " and " << elf_path;

  StartSnapshotContext();

  Status<KernelFile> metadata_file = KernelFile::Open(
      metadata_path, O_CREAT | O_TRUNC, FileMode::kWrite, 0644);
  if (!metadata_file) return MakeError(metadata_file);

  auto f = finally([] { EndSnapshotContext(); });

  Status<void> ret = SnapshotMetadata(*p, *metadata_file);
  if (!ret) return ret;
  return SnapshotElf(p->get_mem_map(), GetSnapshotContext(), elf_path);
}

// Snapshots a process to a stream without touching the filesystem.
// Stream format: [8-byte metadata length LE][metadata bytes][ELF bytes]
Status<void> SnapshotProcToELFStream(Process *p, VectoredWriter &out) {
  LOG(INFO) << "snapshotting proc " << p->get_pid() << " to stream";

  StartSnapshotContext();
  auto f = finally([] { EndSnapshotContext(); });

  // Serialize metadata into a buffer so we can length-prefix it.
  Time t0 = Time::Now();
  std::vector<std::byte> metadata_buf;
  {
    rt::RuntimeLibcGuard guard;
    struct VecWriter {
      std::vector<std::byte> &buf;
      Status<size_t> Write(std::span<const std::byte> src) {
        buf.insert(buf.end(), src.begin(), src.end());
        return src.size();
      }
    } vw{metadata_buf};
    StreamBufferWriter<VecWriter> sbw(vw);
    std::ostream outstream(&sbw);
    cereal::BinaryOutputArchive ar(outstream);
    if (Status<void> ret = FSSnapshot(ar); !ret) return ret;
    ar(p->shared_from_this());
    SerializeUnixSocketState(ar);
  }
  Time t1 = Time::Now();
  LOG(INFO) << "migration sender: serialize took "
            << (t1 - t0).Microseconds() << " us ("
            << metadata_buf.size() << " bytes)";

  if (Status<void> ret =
          WriteU8(out, static_cast<uint8_t>(MigrationType::kStopAndCopy));
      !ret)
    return ret;
  if (Status<void> ret = WriteU64LE(out, metadata_buf.size()); !ret) return ret;
  iovec meta_iov = {metadata_buf.data(), metadata_buf.size()};
  if (Status<void> ret = WritevFull(out, {&meta_iov, 1}); !ret) return ret;

  if (Status<void> ret = SnapshotElfToStream(p->get_mem_map(), GetSnapshotContext(), out); !ret)
    return ret;
  Time t2 = Time::Now();
  LOG(INFO) << "migration sender: transfer took "
            << (t2 - t1).Microseconds() << " us";
  LOG(INFO) << "migration sender: total took "
            << (t2 - t0).Microseconds() << " us";
  return {};
}

Status<void> SnapshotPidToELF(pid_t pid, std::string_view metadata_path,
                              std::string_view elf_path) {
  std::shared_ptr<Process> p = Process::Find(pid);
  if (!p) {
    LOG(WARN) << "couldn't find proc with pid " << pid;
    return MakeError(ESRCH);
  }

  LOG(INFO) << "stopping proc with pid " << pid;

  // TODO(snapshot): child procs, if any exist, should also be stopped + waited.
  p->JobControlStop();
  p->WaitForFullStop();
  auto f = finally([&] {
    if (GetCfg().snapshot_terminate())
      p->DoExit(0);
    else
      p->JobControlContinue();
  });
  return SnapshotProcToELF(p.get(), metadata_path, elf_path);
}

Status<std::shared_ptr<Process>> RestoreProcessFromELF(
    std::string_view metadata_path, std::string_view elf_path) {
  rt::RuntimeLibcGuard guard;

  Status<KernelFile> f = KernelFile::Open(metadata_path, 0, FileMode::kRead);
  if (unlikely(!f)) return MakeError(f);
  StreamBufferReader<KernelFile> w(*f);
  std::istream instream(&w);
  cereal::BinaryInputArchive ar(instream);

  if (Status<void> ret = FSRestore(ar); unlikely(!ret)) return MakeError(ret);
  timings().restore_metadata_start = Time::Now();

  std::shared_ptr<Process> p;
  ar(p);
  SerializeUnixSocketState(ar);
  timings().restore_data_start = Time::Now();

  Status<JunctionFile> elf =
      JunctionFile::Open(p->get_fs(), elf_path, 0, FileMode::kRead);
  if (unlikely(!elf)) return MakeError(elf);

  // Temporary hack: the elf loader will create entries in this fake map,
  // allowing the actual memory map to be restored by cereal.
  MemoryMap mm(nullptr, kMemoryMappingSize);
  mm.MarkAsFake();
  Status<elf_data> ret = LoadELF(mm, *elf, p->get_fs());
  if (GetCfg().restore_populate()) {
    mm.ForEachVMA([](const VMArea &vma) {
      if (!(vma.prot & PROT_READ)) return;
      KernelMAdvise(vma.Addr(), vma.Length(), MADV_POPULATE_READ);
    });
  }

  if (unlikely(!ret)) {
    LOG(ERR) << "Elf load failed: " << ret.error();
    return MakeError(ret);
  };

  if (unlikely(GetCfg().mem_trace())) p->get_mem_map().EnableTracing(*p.get());

  // mark threads as runnable
  // (must be last things to run, this will get the snapshot running)
  p->RunThreads();
  return p;
}

// Restores a process from a stream produced by SnapshotProcToELFStream.
// Stream format: [8-byte metadata length LE][metadata bytes][ELF bytes]
Status<std::shared_ptr<Process>> RestoreProcessFromELFStream(
    VectoredReader &in) {
  Time t0 = Time::Now();
  timings().migration_restore_start = t0;

  // Read and dispatch on migration type.
  uint8_t migration_type = 0;
  iovec type_iov = {&migration_type, sizeof(migration_type)};
  if (Status<void> ret = ReadvFull(in, {&type_iov, 1}); !ret)
    return MakeError(ret);
  if (migration_type != static_cast<uint8_t>(MigrationType::kStopAndCopy)) {
    LOG(ERR) << "unsupported migration type: " << migration_type;
    return MakeError(EINVAL);
  }

  // Read metadata length prefix.
  uint64_t metadata_len = 0;
  {
    iovec iov = {&metadata_len, sizeof(metadata_len)};
    if (Status<void> ret = ReadvFull(in, {&iov, 1}); !ret)
      return MakeError(ret);
  }

  // Read metadata into a buffer.
  std::vector<std::byte> metadata_buf(metadata_len);
  {
    iovec iov = {metadata_buf.data(), metadata_buf.size()};
    if (Status<void> ret = ReadvFull(in, {&iov, 1}); !ret)
      return MakeError(ret);
  }
  Time t1 = Time::Now();
  LOG(INFO) << "migration receiver: metadata transfer took "
            << (t1 - t0).Microseconds() << " us (" << metadata_len << " bytes)";

  // Deserialize metadata — guard scoped here only, network reads above/below
  // can block and must not run with preemption disabled.
  std::shared_ptr<Process> p;
  {
    rt::RuntimeLibcGuard guard;
    struct VecReader {
      std::span<const std::byte> remaining;
      Status<size_t> Read(std::span<std::byte> dst) {
        size_t n = std::min(dst.size(), remaining.size());
        std::copy_n(remaining.begin(), n, dst.begin());
        remaining = remaining.subspan(n);
        return n ? n : Status<size_t>(MakeError(EUNEXPECTEDEOF));
      }
    } vr{metadata_buf};
    StreamBufferReader<VecReader> sbr(vr);
    std::istream instream(&sbr);
    cereal::BinaryInputArchive ar(instream);

    if (Status<void> ret = FSRestore(ar); unlikely(!ret)) return MakeError(ret);
    timings().restore_metadata_start = Time::Now();

    ar(p);
    SerializeUnixSocketState(ar);
    timings().restore_data_start = Time::Now();
  }
  Time t2 = Time::Now();
  LOG(INFO) << "migration receiver: metadata deserialize took "
            << (t2 - t1).Microseconds() << " us";

  // Buffer the ELF data into a tmpfile so LoadELF can seek/mmap it.
  Status<KernelFile> tmp =
      KernelFile::Open("/tmp/junction_migrate.elf", O_CREAT | O_TRUNC,
                       FileMode::kReadWrite, 0600);
  if (unlikely(!tmp)) return MakeError(tmp);

  size_t elf_bytes = 0;
  {
    std::array<std::byte, 65536> buf;
    while (true) {
      iovec iov = {buf.data(), buf.size()};
      Status<size_t> n = in.Readv({&iov, 1});
      if (!n || *n == 0) break;
      elf_bytes += *n;
      iovec wiov = {buf.data(), *n};
      if (Status<void> ret = WritevFull(*tmp, {&wiov, 1}); !ret)
        return MakeError(ret);
    }
  }
  Time t3 = Time::Now();
  LOG(INFO) << "migration receiver: ELF transfer took "
            << (t3 - t2).Microseconds() << " us (" << elf_bytes << " bytes)";

  Status<JunctionFile> elf = JunctionFile::Open(
      p->get_fs(), "/tmp/junction_migrate.elf", 0, FileMode::kRead);
  if (unlikely(!elf)) return MakeError(elf);

  MemoryMap mm(nullptr, kMemoryMappingSize);
  mm.MarkAsFake();
  Status<elf_data> ret = LoadELF(mm, *elf, p->get_fs());
  if (GetCfg().restore_populate()) {
    mm.ForEachVMA([](const VMArea &vma) {
      if (!(vma.prot & PROT_READ)) return;
      KernelMAdvise(vma.Addr(), vma.Length(), MADV_POPULATE_READ);
    });
  }

  if (unlikely(!ret)) {
    LOG(ERR) << "Elf load failed (stream restore): " << ret.error();
    return MakeError(ret);
  }
  Time t4 = Time::Now();
  LOG(INFO) << "migration receiver: ELF deserialize took "
            << (t4 - t3).Microseconds() << " us";
  LOG(INFO) << "migration receiver: total took "
            << (t4 - t0).Microseconds() << " us";

  if (unlikely(GetCfg().mem_trace())) p->get_mem_map().EnableTracing(*p.get());

  timings().migration_restore_done = Time::Now();
  p->RunThreads();
  return p;
}

}  // namespace junction
