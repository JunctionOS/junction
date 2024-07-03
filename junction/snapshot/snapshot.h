// snapshot.h - tools for creating snapshots

#pragma once

extern "C" {
#include <signal.h>
#include <sys/resource.h>
#include <sys/uio.h>

#include "lib/caladan/runtime/defs.h"
}

#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "junction/base/bits.h"
#include "junction/base/error.h"
#include "junction/base/time.h"
#include "junction/bindings/net.h"
#include "junction/kernel/elf.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/proc.h"
#include "junction/kernel/sigframe.h"
#include "junction/kernel/signal.h"

namespace junction {

namespace {
inline size_t GetMinSize(std::span<const uint64_t> buf) {
  auto it = std::find_if(buf.rbegin(), buf.rend(),
                         [](const uint64_t &c) { return c != 0; });
  return std::distance(buf.begin(), it.base());
}

inline size_t GetMinSize(const void *buf, size_t len) {
  assert(len % sizeof(uint64_t) == 0);
  return GetMinSize({reinterpret_cast<const uint64_t *>(buf),
                     len / sizeof(uint64_t)}) *
         sizeof(uint64_t);
}
}  // anonymous namespace

/**
 * Snapshot Context
 */
struct FSMemoryArea {
  char *ptr;
  size_t in_use_size;
  size_t max_size;
};

struct SnapshotContext {
  std::vector<FSMemoryArea> mem_areas_;
};

SnapshotContext &GetSnapshotContext();
void StartSnapshotContext();
void EndSnapshotContext();

/**
 * General utilities
 */
Status<void> SnapshotMetadata(Process &p, KernelFile &file);
Status<void> RestoreVMAProtections(MemoryMap &mm);

/**
 * ELF utilities
 */
Status<void> SnapshotPidToELF(pid_t pid, std::string_view metadata_path,
                              std::string_view elf_path);

Status<void> SnapshotProcToELF(Process *p, std::string_view metadata_path,
                               std::string_view elf_path);

Status<std::shared_ptr<Process>> RestoreProcessFromELF(
    std::string_view metadata_path, std::string_view elf_path);

}  // namespace junction
