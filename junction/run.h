// run.h utilities for starting junction

#pragma once

#include "junction/base/error.h"
#include "junction/kernel/proc.h"

namespace junction {

Status<std::shared_ptr<Process>> CreateFirstProcess(
    std::string_view path, std::vector<std::string_view> &argv,
    const std::vector<std::string_view> &envp);

std::pair<std::vector<std::string>, std::vector<std::string_view>> BuildEnvp();
}  // namespace junction