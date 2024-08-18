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
  len = div_up(len, sizeof(uint64_t));
  return GetMinSize({reinterpret_cast<const uint64_t *>(buf), len}) *
         sizeof(uint64_t);
}
}  // anonymous namespace

struct StartupTimings {
  std::optional<Time> junction_main_start;
  std::optional<Time> restore_start;
  std::optional<Time> exec_start;
  std::optional<Time> restore_metadata_start;
  std::optional<Time> restore_data_start;
  std::optional<Time> first_function_start;
  std::optional<Time> first_function_end;

  Duration CaladanStartTime() {
    assert(junction_main_start);
    return *junction_main_start - Time(0);
  }

  Duration JunctionInitTime() {
    assert(junction_main_start);
    if (exec_start) {
      return *exec_start - *junction_main_start;
    } else {
      assert(restore_start);
      return *restore_start - *junction_main_start;
    }
  }

  Duration ApplicationInitTime() {
    assert(first_function_start && exec_start);
    return *first_function_start - *exec_start;
  }

  Duration FSRestoreTime() {
    assert(restore_metadata_start && restore_start);
    return *restore_metadata_start - *restore_start;
  }

  Duration MetadataRestoreTime() {
    assert(restore_data_start && restore_metadata_start);
    return *restore_data_start - *restore_metadata_start;
  }

  Duration DataRestoreTime() {
    assert(first_function_start && restore_data_start);
    return *first_function_start - *restore_data_start;
  }

  Duration FirstIterTime() {
    assert(first_function_end && first_function_start);
    return *first_function_end - *first_function_start;
  }

  Duration TotalRestoreTime() {
    assert(first_function_start && restore_start);
    return *first_function_start - *restore_start;
  }
};

StartupTimings &timings();

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
  std::vector<std::shared_ptr<DirectoryEntry>> dents;
};

SnapshotContext &GetSnapshotContext();
void StartSnapshotContext();
void EndSnapshotContext();

/**
 * General utilities
 */
Status<void> SnapshotMetadata(Process &p, KernelFile &file);
Status<void> RestoreVMAProtections(MemoryMap &mm);
Status<void> TakeSnapshot(Process *p);

/**
 * ELF utilities
 */
Status<void> SnapshotPidToELF(pid_t pid, std::string_view metadata_path,
                              std::string_view elf_path);

Status<void> SnapshotProcToELF(Process *p, std::string_view metadata_path,
                               std::string_view elf_path);

Status<std::shared_ptr<Process>> RestoreProcessFromELF(
    std::string_view metadata_path, std::string_view elf_path);

/**
 * JIF utilities
 */
Status<void> SnapshotPidToJIF(pid_t pid, std::string_view metadata_path,
                              std::string_view jif_path);

Status<void> SnapshotProcToJIF(Process *p, std::string_view metadata_path,
                               std::string_view jif_path);

Status<std::shared_ptr<Process>> RestoreProcessFromJIF(
    std::string_view metadata_path, std::string_view jif_path);

}  // namespace junction
