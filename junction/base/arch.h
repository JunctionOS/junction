// arch.h - x86 constants and utilities

#pragma once

#include "junction/base/bits.h"

namespace junction {

constexpr size_t kPageSize = 4096;
constexpr size_t kLargePageSize = 2097152;
constexpr size_t kCacheLineSize = 64;

// PageAlign aligns an address upward to the nearest page size
template <typename T>
constexpr T PageAlign(T addr) requires std::is_unsigned_v<T> {
  return AlignUp(addr, kPageSize);
}

// PageAlignDown aligns an address downward to the nearest page size
template <typename T>
constexpr T PageAlignDown(T addr) requires std::is_unsigned_v<T> {
  return AlignDown(addr, kPageSize);
}

}  // namespace junction
