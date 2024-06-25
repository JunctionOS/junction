// run.h utilities for starting junction

#pragma once

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/bindings/runtime.h"
#include "junction/junction.h"
#include "junction/kernel/exec.h"
#include "junction/kernel/stdiofile.h"

namespace junction {

Status<std::shared_ptr<Process>> CreateFirstProcess(
    std::string_view path, std::vector<std::string_view> &argv,
    const std::vector<std::string_view> &envp);

std::pair<std::vector<std::string>, std::vector<std::string_view>> BuildEnvp();
}  // namespace junction