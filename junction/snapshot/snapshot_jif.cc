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

  uint8_t jprot = LinuxProtToJIFProt(prot);

  // Make memory area readable if needed.
  if (filesz && !(prot & PROT_READ)) {
    Status<void> ret = KernelMProtect(startp, filesz, prot | PROT_READ);
    if (!ret) return MakeError(ret);
  }

  // Reduce filesz if possible.
  uint64_t non_zero_sz = PageAlign(GetMinSize(startp, filesz));

  jif_itree_node_t itree;
  itree.InitEmpty();
  size_t n_intervals = 0;

  if (non_zero_sz) {
    // store the file data
    itree.ranges[n_intervals++] = {
        .start = start,
        .end = start + non_zero_sz,
        .offset = iovs.DataSize()  // needs fixing
    };
  }

  if (ref_offset != kUInt64Max && filesz > non_zero_sz) {
    // we have a zero filled range in a file
    itree.ranges[n_intervals++] = {
        .start = start + non_zero_sz,
        .end = start + filesz,
        .offset = kUInt64Max,  // zero
    };
  }

  uint32_t itree_idx = itrees.size();
  if (n_intervals) itrees.push_back(itree);

  uint32_t pathname_offset = kUInt32Max;
  assert((name.size() == 0) == (ref_offset == kUInt64Max));
  if (name.size()) {
    pathname_offset = strings.size();
    strings.insert(strings.end(), name.data(),
                   name.data() + name.size() + 1);  // remember the NULL byte
  }

  phdrs.push_back({
      .vbegin = start,
      .vend = start + memsz,
      .ref_offset = ref_offset,
      .itree_idx = itree_idx,
      .itree_n_nodes = static_cast<uint32_t>(n_intervals ? 1 : 0),
      .pathname_offset = pathname_offset,
      .prot = jprot,
  });

  if (non_zero_sz) iovs.Add(startp, non_zero_sz);
  return {};
}

namespace {

Status<std::tuple<jif_data, IOVAccumulator>> GetJifVmaData(
    MemoryMap &mm, SnapshotContext &ctx) {
  const std::vector<VMArea> vmas = mm.get_vmas();
  const size_t max_n_pheaders = vmas.size() + ctx.mem_areas_.size();
  jif_data jif;
  jif.hdr.magic[0] = 0x77;
  jif.hdr.magic[1] = 'J';
  jif.hdr.magic[2] = 'I';
  jif.hdr.magic[3] = 'F';
  jif.hdr.version = kJifVersion;

  jif.phdrs.reserve(max_n_pheaders);   // vmas
  jif.itrees.reserve(max_n_pheaders);  // vmas
  IOVAccumulator iovs;
  iovs.Reserve(max_n_pheaders);

  for (const VMArea &vma : vmas) {
    if (vma.type == VMType::kFile && vma.file->SnapshotShareable()) {
      const std::string &name = vma.file->get_filename();
      assert(name.size());
      jif.AddPhdr(iovs, vma.prot, vma.start, vma.DataLength(), vma.Length(),
                  vma.offset, name);
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

  jif.hdr.n_pheaders = jif.phdrs.size();
  jif.hdr.strings_size = PageAlign(byte_size(jif.strings));
  jif.hdr.itrees_size = PageAlign(byte_size(jif.itrees));
  jif.hdr.ord_size = 0;
  jif.hdr.n_prefetch = 0;

  size_t data_offset = jif.hdr.data_offset();
  // Make itree offsets absolute in the JIF file.
  for (auto &itree_node : jif.itrees) {
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

  IOVAccumulator jif_iovecs;
  jif_iovecs.Reserve(1 /* header */ + 2 /* pheaders + padding */
                     + 2                /* string section + padding */
                     + 2                /* itree section + padding */
                     + 2                /* ord section + padding */
  );

  // header
  jif_iovecs.Add(&jif.hdr, sizeof(jif_header));

  // pheaders
  jif_iovecs.Add(jif.phdrs);
  jif_iovecs.Pad(padding, kPageSize);

  // strings
  jif_iovecs.Add(jif.strings);
  jif_iovecs.Pad(padding, kPageSize);

  // itrees
  jif_iovecs.Add(jif.itrees);
  jif_iovecs.Pad(padding, kPageSize);

  // ord
  jif_iovecs.Add(jif.ord);
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

  auto f = finally([&] {
    if (GetCfg().snapshot_terminate())
      p->DoExit(0);
    else
      p->Signal(SIGCONT);
  });
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

  DLOG(INFO) << "jif: loading Junction kernel from " << metadata_path
             << " and JIF object file '" << jif_path << "'";

  Status<KernelFile> metadata_file =
      KernelFile::Open(metadata_path, 0, FileMode::kRead);
  if (!metadata_file) return MakeError(metadata_file);

  std::shared_ptr<Process> p;
  StreamBufferReader<KernelFile> w(*metadata_file);
  std::istream instream(&w);
  cereal::BinaryInputArchive ar(instream);

  if (Status<void> ret = FSRestore(ar); unlikely(!ret)) return MakeError(ret);
  timings().restore_metadata_start = Time::Now();
  ar(p);
  timings().restore_data_start = Time::Now();

  Status<KernelFile> jif_file = KernelFile::Open(jif_path, 0, FileMode::kRead);
  if (!jif_file) return MakeError(jif_file);

  if (GetCfg().kernel_restoring()) {
    Status<KernelFile> jifpager_dev =
        KernelFile::Open("/dev/jif_pager", 0, FileMode::kWrite);
    if (unlikely(!jifpager_dev)) return MakeError(jifpager_dev);

    std::span<const std::byte> path_bytes = std::span<const std::byte>(
        reinterpret_cast<std::byte const *>(jif_path.data()), jif_path.size());

    Status<size_t> ret = (*jifpager_dev).Write(path_bytes);

    if (unlikely(!ret)) {
      LOG(ERR) << "Kernel JIF load failed: " << ret.error();
      return MakeError(ret);
    };
  } else {
    Status<jif_data> ret = ::junction::LoadJIF(*jif_file);

    if (unlikely(!ret)) {
      LOG(ERR) << "Userspace JIF load failed: " << ret.error();
      return MakeError(ret);
    };
  }

  if (unlikely(GetCfg().mem_trace())) p->get_mem_map().EnableTracing();

  // mark threads as runnable
  // (must be last things to run, this will get the snapshot running)
  p->RunThreads();
  return p;
}

}  // namespace junction
