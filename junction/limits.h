// limits.h - put all hardcoded limits in this file
// TODO: should any of these be made dynamic/configurable?

#pragma once

#include <cstddef>

#include "junction/base/arch.h"

namespace junction {

// The maximum number of running proccesses.
inline constexpr size_t kMaxProcesses = 1024;
// The size in bytes of the most virtual memory a process can map.
inline constexpr size_t kMemoryMappingSize = (1UL << 34);  // 16 GB
// The size in bytes of the pipe's channel.
inline constexpr size_t kPipeSize = 16 * kPageSize;  // same default as Linux

}  // namespace junction
