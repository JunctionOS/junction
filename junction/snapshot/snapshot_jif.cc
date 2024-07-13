#include <cstdio>
#include <fstream>
#include <iostream>
#include <limits>
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
#include "junction/kernel/jif.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/snapshot/cereal.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

namespace {

Status<std::tuple<jif_data, std::vector<iovec>>> GetJifVmaData(
    MemoryMap &mm, SnapshotContext &ctx) {
  const std::vector<VMArea> vmas = mm.get_vmas();
  const size_t max_n_pheaders = vmas.size() + ctx.mem_areas_.size();
  jif_data jif;
  jif.jif_hdr.jif_magic[0] = 0x77;
  jif.jif_hdr.jif_magic[1] = 'J';
  jif.jif_hdr.jif_magic[2] = 'I';
  jif.jif_hdr.jif_magic[3] = 'F';

  jif.jif_phdrs.reserve(max_n_pheaders);   // vmas
  jif.jif_itrees.reserve(max_n_pheaders);  // vmas
  std::vector<iovec> iovs;
  iovs.reserve(max_n_pheaders);

  uint64_t offset = 0;  // this needs to be fixed after the pheader, itree,
                        // string and ord sections are put in place.
  for (const VMArea &vma : vmas) {
    uint8_t prot = 0;
    if (vma.prot & PROT_EXEC) prot |= kJIFFlagExec;
    if (vma.prot & PROT_WRITE) prot |= kJIFFlagWrite;
    if (vma.prot & PROT_READ) prot |= kJIFFlagRead;

    uint32_t pathname_offset = -1;
    uint64_t ref_offset = -1;

    size_t filesz = vma.DataLength();
    size_t memsz = vma.Length();

    if (jif.jif_itrees.size() > std::numeric_limits<uint32_t>::max()) {
      LOG(ERR) << "overflow of interval trees: more than 32bits of nodes";
      return MakeError(EINVAL);
    }
    uint32_t itree_idx = jif.jif_itrees.size();
    uint32_t itree_n_nodes = 0;  // itree can be empty if filesz == 0
    size_t n_intervals = 0;

    jif_itree_node_t itree;
    memset(&itree, 0xff, sizeof(jif_itree_node_t));  // invalidate itree node
    if (filesz > 0) {
      // store the file data
      itree.ranges[n_intervals] = {
          .start = vma.start,
          .end = vma.start + filesz,
          .offset = offset  // needs fixing
      };

      n_intervals += 1;
    }

    if (memsz > filesz) {
      // we have a zero filled range

      itree.ranges[n_intervals] = {
          .start = vma.start + filesz,
          .end = vma.end,
          .offset = static_cast<uint64_t>(-1),  // zero
      };

      n_intervals += 1;
    }

    if (n_intervals > 0) {
      jif.jif_itrees.push_back(itree);
      itree_n_nodes += 1;
    }

    // Make memory area readable if needed.
    if (filesz > 0 && !(vma.prot & PROT_READ)) {
      auto ret = KernelMProtect(reinterpret_cast<void *>(vma.start), filesz,
                                vma.prot | PROT_READ);
      if (!ret) return MakeError(ret);
    }

    // this creates the info that allows post processing to deduplicate
    // essentially we create a reference segment which is completely overlayed
    // by the data segment contents
    //
    // later on the post processing can clean this up
    //
    if (vma.type == VMType::kFile && vma.file->get_filename().size() > 0) {
      if (jif.jif_strings.size() > std::numeric_limits<uint32_t>::max()) {
        LOG(ERR) << "overflow of strings: more than 32bits of string data";
        return MakeError(EINVAL);
      }
      pathname_offset = jif.jif_strings.size();
      const auto &filename = vma.file->get_filename();
      char const *cstr = filename.c_str();
      jif.jif_strings.insert(
          jif.jif_strings.end(), cstr,
          cstr + filename.size() + 1);  // remember the NUL byte

      ref_offset = vma.offset;
    }

    jif_phdr phdr = {
        .jifp_vbegin = vma.start,
        .jifp_vend = vma.end,
        .jifp_ref_offset = ref_offset,
        .jifp_itree_idx = itree_idx,
        .jifp_itree_n_nodes = itree_n_nodes,
        .jifp_pathname_offset = pathname_offset,
        .jifp_prot = prot,
    };

    jif.jif_phdrs.push_back(phdr);
    if (filesz > 0) {
      offset += filesz;
      iovs.emplace_back(reinterpret_cast<void *>(vma.start), filesz);
    }
  }

  for (const FSMemoryArea &area : ctx.mem_areas_) {
    size_t saved_area = PageAlign(GetMinSize(area.ptr, area.in_use_size));
    size_t memsz = area.max_size;

    if (jif.jif_itrees.size() > std::numeric_limits<uint32_t>::max()) {
      LOG(ERR) << "overflow of interval trees: more than 32bits of nodes";
      return MakeError(EINVAL);
    }
    uint32_t itree_idx = jif.jif_itrees.size();
    uint32_t itree_n_nodes = 0;  // itree can be empty if saved_ares == 0
    size_t n_intervals = 0;

    jif_itree_node_t itree;
    memset(&itree, 0xff, sizeof(jif_itree_node_t));  // invalidate itree node

    if (saved_area > 0) {
      itree.ranges[n_intervals] = {
          .start = reinterpret_cast<uint64_t>(area.ptr),
          .end = reinterpret_cast<uint64_t>(area.ptr) + saved_area,
          .offset = offset  // needs fixing
      };
      n_intervals += 1;
    }

    if (memsz > saved_area) {
      itree.ranges[n_intervals] = {
          .start = reinterpret_cast<uint64_t>(area.ptr) + saved_area,
          .end = reinterpret_cast<uint64_t>(area.ptr) + memsz,
          .offset = static_cast<uint64_t>(-1),  // zero
      };
      n_intervals += 1;
    }

    if (n_intervals > 0) {
      jif.jif_itrees.push_back(itree);
      itree_n_nodes += 1;
    }

    jif_phdr phdr = {
        .jifp_vbegin = reinterpret_cast<uint64_t>(area.ptr),
        .jifp_vend = reinterpret_cast<uint64_t>(area.ptr) + memsz,
        .jifp_ref_offset = static_cast<uint64_t>(-1),
        .jifp_itree_idx = itree_idx,
        .jifp_itree_n_nodes = itree_n_nodes,
        .jifp_pathname_offset = static_cast<uint32_t>(-1),
        .jifp_prot = kJIFFlagRead | kJIFFlagWrite,  // TODO(bsd): ???
    };

    jif.jif_phdrs.push_back(phdr);
    offset += saved_area;
    if (saved_area > 0) {
      iovs.emplace_back(area.ptr, saved_area);
    }
  }

  size_t itrees_size =
      PageAlign(jif.jif_itrees.size() * sizeof(jif_itree_node_t));
  size_t strings_size = PageAlign(jif.jif_strings.size());
  if (itrees_size > std::numeric_limits<uint32_t>::max()) {
    LOG(ERR) << "overflow of interval trees: more than 32bits of itree data";
    return MakeError(EINVAL);
  }
  if (strings_size > std::numeric_limits<uint32_t>::max()) {
    LOG(ERR) << "overflow of strings: more than 32bits of string data";
    return MakeError(EINVAL);
  }
  if (jif.jif_phdrs.size() > std::numeric_limits<uint32_t>::max()) {
    LOG(ERR) << "overflow of pheaders: more than 32bits of pheaders";
    return MakeError(EINVAL);
  }

  jif.jif_hdr.jif_n_pheaders = jif.jif_phdrs.size();
  jif.jif_hdr.jif_strings_size = strings_size;
  jif.jif_hdr.jif_itrees_size = itrees_size;
  jif.jif_hdr.jif_ord_size = PageAlign(static_cast<uint32_t>(0));

  size_t data_offset = jif_data_offset(jif.jif_hdr);
  // fix offsets
  for (auto &itree_node : jif.jif_itrees) {
    for (size_t idx = 0; idx < FANOUT - 1; idx += 1) {
      if (itree_node.ranges[idx].offset != static_cast<uint64_t>(-1)) {
        itree_node.ranges[idx].offset += data_offset;
      }
    }
  }

  return std::make_pair(jif, iovs);
}

Status<void> SnapshotJIF(MemoryMap &mm, SnapshotContext &ctx,
                         std::string_view jif_path) {
  auto ret = GetJifVmaData(mm, ctx);
  if (!ret) return MakeError(ret);
  auto &[jif, iovs] = *ret;

  Status<KernelFile> jif_file =
      KernelFile::Open(jif_path, O_CREAT | O_TRUNC, FileMode::kWrite, 0644);
  if (unlikely(!jif_file)) return MakeError(jif_file);

  std::array<std::byte, 4096> padding{std::byte{0}};
  std::array<std::byte, 4096> ones_padding{std::byte{0xff}};

  std::vector<iovec> jif_iovecs;
  jif_iovecs.reserve(1 /* header */ + 2 /* pheaders + padding */
                     + 2                /* string section + padding */
                     + 2                /* itree section + padding */
                     + 2                /* ord section + padding */
  );

  // header
  { jif_iovecs.emplace_back(&jif.jif_hdr, sizeof(jif_header)); }

  // pheaders
  {
    size_t sz = jif.jif_phdrs.size() * sizeof(jif_phdr);
    jif_iovecs.emplace_back(jif.jif_phdrs.data(), sz);

    size_t total_size = sz + sizeof(jif_header);
    if (total_size != PageAlign(total_size)) {
      jif_iovecs.emplace_back(padding.data(),
                              PageAlign(total_size) - total_size);
    }
  }

  // strings
  {
    size_t sz = jif.jif_strings.size();
    jif_iovecs.emplace_back(jif.jif_strings.data(), sz);

    if (sz != jif.jif_hdr.jif_itrees_size) {
      jif_iovecs.emplace_back(padding.data(),
                              jif.jif_hdr.jif_strings_size - sz);
    }
  }

  // itrees
  {
    size_t sz = jif.jif_itrees.size() * sizeof(jif_itree_node_t);
    jif_iovecs.emplace_back(jif.jif_itrees.data(), sz);

    if (sz != jif.jif_hdr.jif_itrees_size) {
      jif_iovecs.emplace_back(ones_padding.data(),
                              jif.jif_hdr.jif_itrees_size - sz);
    }
  }

  // ord
  {
    size_t sz = jif.jif_ord.size() * sizeof(jif_ord_chunk_t);
    jif_iovecs.emplace_back(jif.jif_ord.data(), sz);

    if (sz != jif.jif_hdr.jif_ord_size) {
      jif_iovecs.emplace_back(padding.data(), jif.jif_hdr.jif_ord_size - sz);
    }
  }

  jif_iovecs.insert(jif_iovecs.end(), iovs.begin(), iovs.end());
  auto write_ret = WritevFull(*jif_file, jif_iovecs);
  if (!write_ret) return write_ret;

  return RestoreVMAProtections(mm);
}

}  // anonymous namespace

Status<void> SnapshotPidToJIF(pid_t pid, std::string_view metadata_path,
                              std::string_view jif_path) {
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
  return SnapshotProcToJIF(p.get(), metadata_path, jif_path);
}

Status<void> SnapshotProcToJIF(Process *p, std::string_view metadata_path,
                               std::string_view jif_path) {
  LOG(INFO) << "snapshotting proc " << p->get_pid() << " into " << metadata_path
            << " and " << jif_path;

  StartSnapshotContext();
  auto f = finally([] { EndSnapshotContext(); });

  // metadata
  {
    Status<KernelFile> metadata_file = KernelFile::Open(
        metadata_path, O_CREAT | O_TRUNC, FileMode::kWrite, 0644);
    if (unlikely(!metadata_file)) return MakeError(metadata_file);

    Status<void> metadata_ret = SnapshotMetadata(*p, *metadata_file);
    if (!metadata_ret) return metadata_ret;
  }

  return SnapshotJIF(p->get_mem_map(), GetSnapshotContext(), jif_path);
}

Status<std::shared_ptr<Process>> RestoreProcessFromJIF(
    std::string_view metadata_path, std::string_view jif_path) {
  rt::RuntimeLibcGuard guard;

  Time start = Time::Now();

  DLOG(INFO) << "jif: loading Junction kernel from " << metadata_path
             << " and JIF object file '" << jif_path << "'";

  Status<KernelFile> metadata_file =
      KernelFile::Open(metadata_path, 0, FileMode::kRead);
  if (!metadata_file) return MakeError(metadata_file);

  std::shared_ptr<Process> p;
  {
    StreamBufferReader<KernelFile> w(*metadata_file);
    std::istream instream(&w);
    cereal::BinaryInputArchive ar(instream);
    ar(p);
  }

  Time end_metadata = Time::Now();

  Status<KernelFile> jif_file = KernelFile::Open(jif_path, 0, FileMode::kRead);
  if (!jif_file) return MakeError(jif_file);

  Status<jif_data> ret = ::junction::LoadJIF(*jif_file);

  Time end_jif = Time::Now();

  if (!ret) {
    LOG(ERR) << "JIF load failed: " << ret.error();
    return MakeError(ret);
  };

  LOG(INFO) << "restore time " << (end_jif - start).Microseconds()
            << " metadata: " << (end_metadata - start).Microseconds()
            << " jif: " << (end_jif - end_metadata).Microseconds();

  if (unlikely(GetCfg().mem_trace_timeout() > 0)) {
    p->get_mem_map().EnableTracing();
  }
  // mark threads as runnable
  // (must be last things to run, this will get the snapshot running)
  p->RunThreads();
  return p;
}

}  // namespace junction
