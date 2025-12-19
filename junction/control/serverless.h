
#pragma once

#include <memory>

#include "junction/base/error.h"

namespace junction {

class Process;

Status<void> SetupServerlessChannel(std::string_view name);
void WarmupAndSnapshot(std::shared_ptr<Process> proc, std::string_view name,
                       std::string_view arg);

pid_t GetLastBlockedTid(std::string_view name);
std::string InvokeChan(std::string_view name, std::string arg);
void RunRestored(std::shared_ptr<Process> proc, std::string_view name,
                 std::string_view arg);
}  // namespace junction
