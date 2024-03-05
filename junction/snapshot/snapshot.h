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

void SnapshotMetadata(Process &p, std::string_view metadata_path);

std::pair<std::shared_ptr<Process>, thread_tf> RestoreProcess(
    std::string_view metadata_path);

}  // namespace junction
