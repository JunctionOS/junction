
#pragma once

#include <memory>

#include "junction/base/error.h"

namespace junction {

class Process;

Status<void> SetupServerlessChannel(int chan);
void WarmupAndSnapshot(std::shared_ptr<Process> proc, int chan_id,
                       std::string_view arg);

std::string InvokeChan(int chan, std::string arg);
void RunRestored(std::shared_ptr<Process> proc, int chan_id,
                 std::string_view arg);
}  // namespace junction