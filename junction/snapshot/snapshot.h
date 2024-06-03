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

Status<void> SnapshotPid(pid_t pid, std::string_view metadata_path,
                         std::string_view elf_path);
Status<std::shared_ptr<Process>> RestoreProcess(std::string_view metadata_path,
                                                std::string_view elf_path);

}  // namespace junction
