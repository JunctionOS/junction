#include <iostream>

extern "C" {
#include <fcntl.h>
#include <signal.h>
}

#include "junction/base/error.h"
#include "junction/base/finally.h"
#include "junction/fs/file.h"
#include "junction/fs/memfs/memfs.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/usys.h"
#include "junction/snapshot/cereal.h"
#include "junction/snapshot/jif.h"
#include "junction/snapshot/snapshot.h"

namespace junction {

template <typename T>
size_t byte_size(const std::vector<T> &vec) {
  return sizeof(T) * vec.size();
}

class IOVAccumulator {
 public:
  IOVAccumulator() = default;

  [[nodiscard]] size_t DataSize() const { return data_size_; }
  [[nodiscard]] const std::vector<iovec> &Vec() const { return vec_; }
  void Reserve(size_t n) { vec_.reserve(n); }

  void Add(void *iov_base, size_t iov_len) {
    vec_.emplace_back(iov_base, iov_len);
    data_size_ += iov_len;
  }
  void Add(iovec v) { Add(v.iov_base, v.iov_len); }

  template <typename T>
  void Add(std::vector<T> &vec) {
    Add(vec.data(), byte_size(vec));
  }

  void Pad(std::span<std::byte> padding, size_t alignment) {
    assert(padding.size() >= alignment - 1);
    if (data_size_ % alignment == 0) return;
    Add(padding.data(), alignment - (data_size_ % alignment));
  }

 private:
  std::vector<iovec> vec_;
  size_t data_size_{0};
};

Status<void> jif_data::AddPhdr(IOVAccumulator &iovs, uint8_t prot,
                               uintptr_t start, size_t filesz, size_t memsz,
                               size_t ref_offset, std::string_view name) {
  void *startp = reinterpret_cast<void *>(start);

  // TODO: make JIF use the same bits as the Linux kernel.
  uint8_t jprot = 0;
  if (prot & PROT_EXEC) jprot |= kJIFFlagExec;
  if (prot & PROT_WRITE) jprot |= kJIFFlagWrite;
  if (prot & PROT_READ) jprot |= kJIFFlagRead;

  // Make memory area readable if needed.
  if (filesz && !(prot & PROT_READ)) {
    Status<void> ret = KernelMProtect(startp, filesz, prot | PROT_READ);
    if (!ret) return MakeError(ret);
  }

  // Reduce filesz if possible.
  filesz = PageAlign(GetMinSize(startp, filesz));

  jif_itree_node_t itree;
  itree.InitEmpty();
  size_t n_intervals = 0;

  if (filesz) {
    // store the file data
    itree.ranges[n_intervals++] = {
        .start = start,
        .end = start + filesz,
        .offset = iovs.DataSize()  // needs fixing
    };
  }

  if (memsz > filesz) {
    // we have a zero filled range
    itree.ranges[n_intervals++] = {
        .start = start + filesz,
        .end = start + memsz,
        .offset = kUInt64Max,  // zero
    };
  }

  uint32_t itree_idx = jif_itrees.size();
  if (n_intervals) jif_itrees.push_back(itree);

  uint32_t pathname_offset = kUInt32Max;
  assert((name.size() == 0) == (ref_offset == kUInt64Max));
  if (name.size()) {
    pathname_offset = jif_strings.size();
    jif_strings.insert(
        jif_strings.end(), name.data(),
        name.data() + name.size() + 1);  // remember the NULL byte
  }

  jif_phdrs.push_back({
      .jifp_vbegin = start,
      .jifp_vend = start + memsz,
      .jifp_ref_offset = ref_offset,
      .jifp_itree_idx = itree_idx,
      .jifp_itree_n_nodes = static_cast<uint32_t>(n_intervals ? 1 : 0),
      .jifp_pathname_offset = pathname_offset,
      .jifp_prot = jprot,
  });

  if (filesz) iovs.Add(startp, filesz);
  return {};
}

namespace {

Status<std::tuple<jif_data, IOVAccumulator>> GetJifVmaData(
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
  IOVAccumulator iovs;
  iovs.Reserve(max_n_pheaders);

  for (const VMArea &vma : vmas) {
    if (vma.type == VMType::kFile) {
      const std::string &name = vma.file->get_filename();
      // TODO - some files don't have names because they are mmaped'd memfs
      // segments. We need to handle sharing for these VMAs on restore properly.
      jif.AddPhdr(iovs, vma.prot, vma.start, vma.DataLength(), vma.Length(),
                  name.size() ? vma.offset : kUInt64Max, name);
    } else {
      jif.AddPhdr(iovs, vma.prot, vma.start, vma.DataLength(), vma.Length(),
                  kUInt64Max, {});
    }
  }

  for (const FSMemoryArea &area : ctx.mem_areas_) {
    jif.AddPhdr(iovs, PROT_READ | PROT_WRITE,
                reinterpret_cast<uintptr_t>(area.ptr), area.in_use_size,
                area.max_size, kUInt64Max, {});
  }

  jif.jif_hdr.jif_n_pheaders = jif.jif_phdrs.size();
  jif.jif_hdr.jif_strings_size = PageAlign(byte_size(jif.jif_strings));
  jif.jif_hdr.jif_itrees_size = PageAlign(byte_size(jif.jif_itrees));
  jif.jif_hdr.jif_ord_size = 0;

  size_t data_offset = jif_data_offset(jif.jif_hdr);
  // Make itree offsets absolute in the JIF file.
  for (auto &itree_node : jif.jif_itrees) {
    for (auto &ival : itree_node.ranges) {
      if (ival.HasOffset()) ival.offset += data_offset;
    }
  }

  return std::make_pair(std::move(jif), std::move(iovs));
}

Status<void> SnapshotJIF(MemoryMap &mm, SnapshotContext &ctx,
                         std::string_view jif_path) {
  auto ret = GetJifVmaData(mm, ctx);
  if (!ret) return MakeError(ret);
  auto &[jif, iovs] = *ret;

  Status<KernelFile> jif_file =
      KernelFile::Open(jif_path, O_CREAT | O_TRUNC, FileMode::kWrite, 0644);
  if (unlikely(!jif_file)) return MakeError(jif_file);

  std::array<std::byte, kPageSize> padding{std::byte{0}};
  std::array<std::byte, kPageSize> ones_padding{std::byte{0xff}};

  IOVAccumulator jif_iovecs;
  jif_iovecs.Reserve(1 /* header */ + 2 /* pheaders + padding */
                     + 2                /* string section + padding */
                     + 2                /* itree section + padding */
                     + 2                /* ord section + padding */
  );

  // header
  jif_iovecs.Add(&jif.jif_hdr, sizeof(jif_header));

  // pheaders
  jif_iovecs.Add(jif.jif_phdrs);
  jif_iovecs.Pad(padding, kPageSize);

  // strings
  jif_iovecs.Add(jif.jif_strings);
  jif_iovecs.Pad(padding, kPageSize);

  // itrees
  jif_iovecs.Add(jif.jif_itrees);
  // TODO: This could probably be zero padding too?
  jif_iovecs.Pad(ones_padding, kPageSize);

  // ord
  jif_iovecs.Add(jif.jif_ord);
  jif_iovecs.Pad(padding, kPageSize);

  if (jif_iovecs.DataSize() > std::numeric_limits<uint32_t>::max()) {
    LOG(ERR) << "overflow of jif metadata: more than 4GB of data";
    return MakeError(EINVAL);
  }

  if (Status<void> ret = WritevFull(*jif_file, jif_iovecs.Vec()); !ret)
    return ret;

  if (Status<void> ret = WritevFull(*jif_file, iovs.Vec()); !ret) return ret;

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

  if (unlikely(!ret)) {
    LOG(ERR) << "JIF load failed: " << ret.error();
    return MakeError(ret);
  };

  LOG(INFO) << "restore time " << (end_jif - start).Microseconds()
            << " metadata: " << (end_metadata - start).Microseconds()
            << " jif: " << (end_jif - end_metadata).Microseconds();

  if (unlikely(GetCfg().mem_trace_timeout())) p->get_mem_map().EnableTracing();

  // mark threads as runnable
  // (must be last things to run, this will get the snapshot running)
  p->RunThreads();
  return p;
}

}  // namespace junction
