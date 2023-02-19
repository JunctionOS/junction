// limits.h - put all hardcoded limits in this file
// TODO: should any of these be made dynamic/configurable?

#pragma once

#include <cstddef>

namespace junction {

// The maximum number of running proccesses.
constexpr size_t kMaxProcesses = 1024;
// The size in bytes of the most virtual memory a process can map.
constexpr size_t kMemoryMappingSize = (1UL << 34);  // 16 GB

}  // namespace junction
