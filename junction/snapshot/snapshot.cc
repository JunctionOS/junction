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

static std::unique_ptr<SnapshotContext> cur_context;

SnapshotContext &GetSnapshotContext() {
  if (unlikely(!cur_context)) throw std::runtime_error("not doing a snapshot");
  return *cur_context.get();
}

void StartSnapshotContext() {
  assert(!cur_context);
  if (!GetCfg().expecting_snapshot()) {
    LOG(WARN) << "WARNING: starting snapshot on runtime was not expecting it; "
                 "consider re-running with the --snapshot_enabled flag";
  }
  cur_context.reset(new SnapshotContext);
}

void EndSnapshotContext() {
  assert(cur_context);
  cur_context.reset();
}
Status<void> SnapshotMetadata(Process &p, KernelFile &file) {
  if (Status<void> ret = FSSnapshotPrepare(); !ret) return ret;

  rt::RuntimeLibcGuard guard;

  StreamBufferWriter<KernelFile> w(file);
  std::ostream outstream(&w);
  cereal::BinaryOutputArchive ar(outstream);
  ar(p.shared_from_this());
  return {};
}

Status<void> RestoreVMAProtections(MemoryMap &mm) {
  const std::vector<VMArea> vmas = mm.get_vmas();
  for (const VMArea &vma : vmas) {
    if (vma.prot & PROT_READ) continue;

    size_t filesz = vma.DataLength();
    if (!filesz) continue;

    Status<void> ret =
        KernelMProtect(reinterpret_cast<void *>(vma.start), filesz, vma.prot);

    if (!ret) return MakeError(ret);
  }
  return {};
}

}  // namespace junction
