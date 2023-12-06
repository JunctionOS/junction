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
#include <vector>

#include "junction/base/bits.h"
#include "junction/base/error.h"
#include "junction/base/time.h"
#include "junction/bindings/net.h"
#include "junction/kernel/elf.h"
#include "junction/kernel/ksys.h"
#include "junction/kernel/sigframe.h"
#include "junction/kernel/signal.h"

namespace junction {

class Snapshotter {
 public:
  static Status<Snapshotter> Open(uint64_t entry_addr, std::vector<elf_phdr>,
                                  std::string_view elf_path,
                                  std::string_view metadata_path);

  // Move support.
  Snapshotter(Snapshotter &&c) noexcept = default;
  Snapshotter &operator=(Snapshotter &&c) = default;

  // disable copy.
  Snapshotter(const Snapshotter &) = delete;
  Snapshotter &operator=(const Snapshotter &) = delete;

  Status<size_t> ElfWritev(std::span<const iovec> iov) &;
  void MetadataPush(std::span<const std::byte> buf) &;
  Status<size_t> MetadataFlush() &;

 private:
  Snapshotter() {}
  Snapshotter(KernelFile &&elf, KernelFile &&metadata)
      : elf_(std::move(elf)), metadata_(std::move(metadata)) {}
  Snapshotter(int elf_fd, KernelFile &&metadata)
      : elf_(KernelFile(elf_fd)), metadata_(std::move(metadata)) {}
  Snapshotter(KernelFile &&elf, int metadata_fd)
      : elf_(std::move(elf)), metadata_(KernelFile(metadata_fd)) {}
  Snapshotter(int elf_fd, int metadata_fd)
      : elf_(KernelFile(elf_fd)), metadata_(KernelFile(metadata_fd)) {}

  KernelFile elf_ = KernelFile(2);
  KernelFile metadata_ = KernelFile(2);
  std::vector<iovec> serialized_metadata_;
};

}  // namespace junction
