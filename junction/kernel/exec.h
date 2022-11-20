// exec.h- junction support for launching elf binaries

#pragma once

#include <string_view>
#include <vector>

#include "junction/base/error.h"
#include "junction/bindings/thread.h"

namespace junction {

Status<thread_t *> Exec(std::string_view pathname,
                        std::vector<std::string_view> argv,
                        std::vector<std::string_view> envp);

}  // namespace junction
