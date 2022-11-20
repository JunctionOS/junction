// exec.h- junction support for launching elf binaries

#pragma once

#include <string_view>
#include <vector>

#include "junction/base/error.h"
#include "junction/bindings/thread.h"

namespace junction {

Status<thread_t *> Exec(std::string_view pathname,
                        const std::vector<std::string_view> &argv,
                        const std::vector<std::string_view> &envp);

}  // namespace junction
