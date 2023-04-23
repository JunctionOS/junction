// exec.h - support for launching elf binaries

#pragma once

#include <string_view>
#include <vector>

#include "junction/base/error.h"
#include "junction/bindings/thread.h"
#include "junction/kernel/proc.h"

namespace junction {

// Execute a binary in a process, replacing any existing memory mappings
//
// The first thread is created and marked ready, so it will start running before
// this returns (if successful).
Status<void> Exec(Process &p, std::string_view pathname,
                  const std::vector<std::string_view> &argv,
                  const std::vector<std::string_view> &envp);

}  // namespace junction
