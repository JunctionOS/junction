// arch.h - x86 constants and utilities

#pragma once

#include "junction/base/bits.h"

namespace junction {

constexpr size_t kPageSize = 4096;
constexpr size_t kLargePageSize = 2097152;
constexpr size_t kCacheLineSize = 64;

// page_align aligns an address upward to the nearest page size
template <typename T>
constexpr T page_align(T addr) requires std::is_unsigned_v<T> {
  return align_up(addr, kPageSize);
}

// page_align_down aligns an address downward to the nearest page size
template <typename T>
constexpr T page_align_down(T addr) requires std::is_unsigned_v<T> {
  return align_down(addr, kPageSize);
}

}  // namespace junction
